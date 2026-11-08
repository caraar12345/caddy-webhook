"""Deploy Wall Dash from its GitHub Actions build.

github.com/caraar12345/home-assistant-wall-dash builds on every push to main and
uploads one artifact, `wall-dash`, holding `wall-dash.tar.gz`:

    www/                        -> /homeassistant/www/wall-dash  (served at /local/wall-dash/)
    custom_components/wall_dash -> /homeassistant/custom_components/wall_dash

GitHub sends a `workflow_run` webhook when the build finishes. We download the
run's artifact with a read-only token and write it into HA's config, so nothing
needs SSH into Home Assistant.

- www/ is overwritten in place, assets first and index.html/entry.json last, so a
  page loading mid-deploy never points at files that aren't there yet. Old hashed
  assets are kept until they're older than HA's 31-day /local/ cache, as the old
  deploy.sh did, so a panel still running an old build keeps working.
- The integration is swapped in whole, and only when it changed. HA needs a
  restart to load it, so we raise a persistent notification saying so.
- Every deploy fires `wall_dash_deployed` on HA's event bus, for automations
  (e.g. pressing the Echo Show's reload button).

Pushes to the configured branch deploy; so does running the workflow by hand
(workflow_dispatch) on any branch, to try a branch on the panels. Re-running an
older run redeploys it, which is how to roll back.
"""

from __future__ import annotations

import filecmp
import hashlib
import json
import os
import shutil
import tarfile
import tempfile
import threading
import time
import zipfile
from dataclasses import dataclass

import httpx
import logfire
from discord_webhook import DiscordEmbed, DiscordWebhook

ARTIFACT_NAME = "wall-dash"
TARBALL_NAME = "wall-dash.tar.gz"
ASSET_MAX_AGE = 31 * 86400
# Written last, once everything they point at is in place
ENTRY_FILES = {"index.html", "entry.json", "version.json"}

SUPERVISOR_CORE_API = "http://supervisor/core/api"
GITHUB_API_HEADERS = {
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}


@dataclass(frozen=True)
class Settings:
    github_token: str | None
    repo: str
    branch: str
    workflow: str
    www_dir: str
    integration_dir: str
    discord_webhook_url: str | None
    notify_discord_user: str | None


def load_settings(options: dict) -> Settings:
    """Settings from the add-on's options (or the environment, outside HA)."""

    def opt(key: str, default: str | None = None) -> str | None:
        value = options.get(key)
        if value is None:
            value = os.getenv(key.upper())
        return value if value not in (None, "") else default

    return Settings(
        github_token=opt("wall_dash_github_token"),
        repo=opt("wall_dash_repo", "caraar12345/home-assistant-wall-dash"),
        branch=opt("wall_dash_branch", "main"),
        workflow=opt("wall_dash_workflow", ".github/workflows/deploy.yaml"),
        www_dir=opt("wall_dash_www_dir", "/homeassistant/www/wall-dash"),
        integration_dir=opt(
            "wall_dash_integration_dir", "/homeassistant/custom_components/wall_dash"
        ),
        discord_webhook_url=opt("discord_webhook_url"),
        notify_discord_user=(
            str(options["notify_discord_user"])
            if options.get("notify_discord_user")
            else os.getenv("NOTIFY_DISCORD_USER")
        ),
    )


def should_deploy(event: str | None, payload: dict, settings: Settings) -> str | None:
    """None if this webhook is a finished build to deploy, else why it's ignored."""
    if event != "workflow_run":
        return f"not a workflow_run event ({event})"
    if payload.get("action") != "completed":
        return f"run not completed ({payload.get('action')})"
    repo = (payload.get("repository") or {}).get("full_name")
    if repo != settings.repo:
        return f"not the Wall Dash repo ({repo})"
    run = payload.get("workflow_run") or {}
    if run.get("path") != settings.workflow:
        return f"not the deploy workflow ({run.get('path')})"
    if run.get("conclusion") != "success":
        return f"run didn't succeed ({run.get('conclusion')})"
    # A hand-started run deploys whatever branch it was started on
    if run.get("event") != "workflow_dispatch" and run.get("head_branch") != settings.branch:
        return f"not {settings.branch} ({run.get('head_branch')})"
    return None


@dataclass(frozen=True)
class DeployResult:
    commit: str
    branch: str
    run_url: str
    devices: list[str]
    files_written: int
    assets_pruned: int
    integration_changed: bool


_lock = threading.Lock()


def deploy_run(run: dict, settings: Settings) -> None:
    """Background task: deploy one finished run and report how it went."""
    commit = run.get("head_sha", "")
    with _lock, logfire.span("Deploying Wall Dash {commit}", commit=commit[:7]):
        try:
            result = _deploy(run, settings)
        except Exception as e:
            logfire.error("Wall Dash deploy failed", _exc_info=True)
            _discord_failure(run, settings, e)
            return
        logfire.info(
            "Deployed Wall Dash {commit}",
            commit=commit[:7],
            files_written=result.files_written,
            assets_pruned=result.assets_pruned,
            integration_changed=result.integration_changed,
        )
        _tell_home_assistant(result)
        _discord_success(result, settings)


def _deploy(run: dict, settings: Settings) -> DeployResult:
    if not settings.github_token:
        raise RuntimeError("wall_dash_github_token isn't set")
    parent = os.path.dirname(os.path.normpath(settings.www_dir))
    os.makedirs(parent, exist_ok=True)
    # Unpack beside the target, on the same filesystem, so files move in with a rename
    staging = tempfile.mkdtemp(prefix=".wall-dash-deploy-", dir=parent)
    try:
        tarball = os.path.join(staging, TARBALL_NAME)
        _download_artifact(run, settings.github_token, tarball)
        unpacked = os.path.join(staging, "unpacked")
        with tarfile.open(tarball) as tar:
            tar.extractall(unpacked, filter="data")

        www = os.path.join(unpacked, "www")
        integration = os.path.join(unpacked, "custom_components", "wall_dash")
        if not os.path.isfile(os.path.join(www, "index.html")):
            raise RuntimeError("artifact has no www/index.html")
        if not os.path.isfile(os.path.join(integration, "manifest.json")):
            raise RuntimeError("artifact has no custom_components/wall_dash/manifest.json")
        _check_version(www, run)

        devices = sorted(
            d
            for d in os.listdir(www)
            if os.path.isfile(os.path.join(www, d, "index.html"))
        )
        files_written = _copy_www(www, settings.www_dir)
        assets_pruned = _prune_assets(settings.www_dir, time.time() - ASSET_MAX_AGE)
        integration_changed = _swap_integration(integration, settings.integration_dir)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    return DeployResult(
        commit=run["head_sha"],
        branch=run.get("head_branch") or "",
        run_url=run.get("html_url") or "",
        devices=devices,
        files_written=files_written,
        assets_pruned=assets_pruned,
        integration_changed=integration_changed,
    )


def _download_artifact(run: dict, token: str, dest: str) -> None:
    headers = {**GITHUB_API_HEADERS, "Authorization": f"Bearer {token}"}
    # httpx drops Authorization when the download redirects to blob storage
    with httpx.Client(headers=headers, follow_redirects=True, timeout=60) as client:
        listing = client.get(run["artifacts_url"], params={"name": ARTIFACT_NAME})
        listing.raise_for_status()
        artifacts = [
            a
            for a in listing.json().get("artifacts", [])
            if a.get("name") == ARTIFACT_NAME and not a.get("expired")
        ]
        if not artifacts:
            raise RuntimeError(f"run has no unexpired '{ARTIFACT_NAME}' artifact")

        zip_path = dest + ".zip"
        with client.stream("GET", artifacts[0]["archive_download_url"]) as response:
            response.raise_for_status()
            with open(zip_path, "wb") as f:
                for chunk in response.iter_bytes():
                    f.write(chunk)

    with zipfile.ZipFile(zip_path) as z:
        if TARBALL_NAME not in z.namelist():
            raise RuntimeError(f"artifact doesn't contain {TARBALL_NAME}")
        with z.open(TARBALL_NAME) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
    os.remove(zip_path)


def _check_version(www: str, run: dict) -> None:
    """The build stamps its commit into version.json: make sure it's this run's."""
    try:
        with open(os.path.join(www, "version.json")) as f:
            built = json.load(f).get("commit")
    except FileNotFoundError:
        return
    if built and built != run.get("head_sha"):
        raise RuntimeError(f"artifact is {built[:7]}, run is {run.get('head_sha', '')[:7]}")


def _copy_www(src: str, dest: str) -> int:
    """Move src's files over dest's, entry points last. Returns files written."""
    files = []
    for root, _, names in os.walk(src):
        for name in names:
            files.append(os.path.relpath(os.path.join(root, name), src))
    files.sort(key=lambda rel: (os.path.basename(rel) in ENTRY_FILES, rel))

    written = 0
    now = time.time()
    for rel in files:
        source, target = os.path.join(src, rel), os.path.join(dest, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        if os.path.isfile(target) and filecmp.cmp(source, target, shallow=False):
            # Unchanged (the emoji, a hashed asset): leave it, but mark it current
            # so pruning only removes assets no build has shipped for 31 days
            os.utime(target, (now, now))
            continue
        os.replace(source, target)
        os.utime(target, (now, now))
        written += 1
    return written


def _prune_assets(www_dir: str, cutoff: float) -> int:
    """Delete files under any assets/ directory last shipped before cutoff."""
    pruned = 0
    for root, _, names in os.walk(www_dir):
        if "assets" not in os.path.relpath(root, www_dir).split(os.sep):
            continue
        for name in names:
            path = os.path.join(root, name)
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                pruned += 1
    return pruned


def _tree_hash(path: str) -> str | None:
    if not os.path.isdir(path):
        return None
    digest = hashlib.sha256()
    for root, dirs, names in os.walk(path):
        dirs[:] = sorted(d for d in dirs if d != "__pycache__")
        for name in sorted(names):
            file = os.path.join(root, name)
            digest.update(os.path.relpath(file, path).encode() + b"\0")
            with open(file, "rb") as f:
                digest.update(hashlib.sha256(f.read()).digest())
    return digest.hexdigest()


def _swap_integration(src: str, dest: str) -> bool:
    """Replace dest with src whole, so a deleted file doesn't linger. Returns
    whether anything changed."""
    if os.path.islink(dest):
        os.remove(dest)  # the old way to install it
    elif _tree_hash(src) == _tree_hash(dest):
        return False
    parent = os.path.dirname(os.path.normpath(dest))
    os.makedirs(parent, exist_ok=True)
    incoming = os.path.join(parent, ".wall_dash.new")
    outgoing = os.path.join(parent, ".wall_dash.old")
    for leftover in (incoming, outgoing):
        shutil.rmtree(leftover, ignore_errors=True)
    # src may be on another filesystem from custom_components
    shutil.copytree(src, incoming)
    if os.path.isdir(dest):
        os.rename(dest, outgoing)
    os.rename(incoming, dest)
    shutil.rmtree(outgoing, ignore_errors=True)
    return True


def _tell_home_assistant(result: DeployResult) -> None:
    """Fire wall_dash_deployed, and ask for a restart if the integration changed.

    Needs `homeassistant_api: true`; outside HA (no SUPERVISOR_TOKEN) it's skipped.
    """
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return
    try:
        with httpx.Client(
            base_url=SUPERVISOR_CORE_API,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        ) as ha:
            ha.post(
                "/events/wall_dash_deployed",
                json={
                    "commit": result.commit,
                    "branch": result.branch,
                    "devices": result.devices,
                    "integration_changed": result.integration_changed,
                },
            ).raise_for_status()
            if result.integration_changed:
                ha.post(
                    "/services/persistent_notification/create",
                    json={
                        "notification_id": "wall_dash_deployed",
                        "title": "Wall Dash integration updated",
                        "message": (
                            f"Deployed `{result.commit[:7]}`, which changes the "
                            "wall_dash integration. Restart Home Assistant to load it."
                        ),
                    },
                ).raise_for_status()
    except Exception:
        logfire.error("Couldn't tell Home Assistant about the deploy", _exc_info=True)


def _discord(settings: Settings, embed: DiscordEmbed) -> None:
    if not settings.discord_webhook_url:
        return
    mention = f"<@{settings.notify_discord_user}>" if settings.notify_discord_user else None
    webhook = DiscordWebhook(url=settings.discord_webhook_url, content=mention)
    webhook.add_embed(embed)
    try:
        webhook.execute()
    except Exception:
        logfire.error("Failed to post to Discord", _exc_info=True)


def _commit_link(settings: Settings, commit: str) -> str:
    return f"[{commit[:7]}](https://github.com/{settings.repo}/commit/{commit})"


def _discord_success(result: DeployResult, settings: Settings) -> None:
    lines = [
        f"{_commit_link(settings, result.commit)} on `{result.branch}`",
        f"Devices: {', '.join(result.devices) or 'none'}",
        f"{result.files_written} files written, {result.assets_pruned} old assets pruned",
    ]
    if result.integration_changed:
        lines.append("**Integration changed: restart Home Assistant to load it.**")
    embed = DiscordEmbed(
        title="Wall Dash deployed", description="\n".join(lines), color="00ff44"
    )
    if result.run_url:
        embed.set_url(result.run_url)
    _discord(settings, embed)


def _discord_failure(run: dict, settings: Settings, error: Exception) -> None:
    commit = run.get("head_sha", "")
    description = (
        f"{_commit_link(settings, commit)} on `{run.get('head_branch')}`\n"
        f"```\n{str(error)[-3500:]}\n```"
    )
    embed = DiscordEmbed(
        title="Wall Dash deploy failed", description=description, color="ff005e"
    )
    if run.get("html_url"):
        embed.set_url(run["html_url"])
    _discord(settings, embed)
