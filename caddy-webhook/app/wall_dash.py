"""Deploy Wall Dash from its signed GitHub Actions builds.

github.com/caraar12345/home-assistant-wall-dash's deploy workflow builds every
push to main and every pull request, signs the tarball with Sigstore, and
uploads one artifact, `wall-dash`:

    wall-dash.tar.gz              www/ and custom_components/wall_dash
    wall-dash.tar.gz.sigstore.json

GitHub's webhook only says "run N finished". Everything else comes from the
API: the run (workflow, trigger, branch, conclusion, commit), then its artifact.
The tarball must verify against its Sigstore bundle, pinned to this repo, the
deploy workflow at the run's ref, and run N, before anything is unpacked.

- main (a push, or running the workflow by hand) deploys production:
  www/ to /homeassistant/www/wall-dash (/local/wall-dash/), overwritten in
  place with entry points last; assets no build has shipped for 31 days are
  pruned. The integration is swapped in whole, only when it changed, with a
  persistent notification asking for a restart. Fires `wall_dash_deployed`.
- A pull request (from this repo) deploys a preview: www/ to
  /share/wall-dash/pr/<n>/, swapped in whole, which Caddy serves internally at
  hass-new.adhd.energy/wall-dash/pr/<n>/. Its emoji are a symlink to one
  shared copy. The integration is never deployed from a PR.
- Closing a PR removes its preview; every deploy also sweeps away previews of
  PRs that aren't open any more.

Re-running an older main run redeploys it, which is how to roll back.
"""

from __future__ import annotations

import filecmp
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import threading
import time
from dataclasses import dataclass, field

import httpx
import logfire
from discord_webhook import DiscordEmbed

from app import notify, provenance
from app.github import GitHub
from app.settings import NotifySettings, WallDashSettings

ARTIFACT_NAME = "wall-dash"
TARBALL_NAME = "wall-dash.tar.gz"
BUNDLE_NAME = TARBALL_NAME + ".sigstore.json"
ASSET_MAX_AGE = 31 * 86400
# Written last, once everything they point at is in place
ENTRY_FILES = {"index.html", "entry.json", "version.json"}
SHARED_EMOJI = "_emoji"
SUPERVISOR_CORE_API = "http://supervisor/core/api"

_lock = threading.Lock()


# --- Which build is this? ---------------------------------------------------


@dataclass(frozen=True)
class Production:
    ref: str


@dataclass(frozen=True)
class Preview:
    number: int | None  # None: look it up by branch

    @property
    def ref(self) -> str:
        return f"refs/pull/{self.number}/merge"


def classify(run: dict, settings: WallDashSettings) -> Production | Preview | str:
    """What to deploy for a run (from the API), or why it's ignored."""
    if run.get("path") != settings.workflow:
        return f"not the deploy workflow ({run.get('path')})"
    if (run.get("repository") or {}).get("full_name") != settings.repo:
        return "not the Wall Dash repo"
    if run.get("status") != "completed" or run.get("conclusion") != "success":
        return f"run didn't succeed ({run.get('status')}/{run.get('conclusion')})"
    if (run.get("head_repository") or {}).get("full_name") != settings.repo:
        return "built from a fork"

    event = run.get("event")
    if event in ("push", "workflow_dispatch"):
        if run.get("head_branch") != settings.branch:
            return f"{event} on {run.get('head_branch')}, not {settings.branch}"
        return Production(ref=f"refs/heads/{settings.branch}")
    if event == "pull_request":
        for pr in run.get("pull_requests") or []:
            if (pr.get("head") or {}).get("sha") == run.get("head_sha"):
                return Preview(number=int(pr["number"]))
        return Preview(number=None)
    return f"not a deploy trigger ({event})"


def should_fetch(event: str | None, payload: dict, settings: WallDashSettings) -> str | None:
    """Cheap filter on the (signed) payload before asking the API, which decides."""
    if event != "workflow_run":
        return f"not a workflow_run event ({event})"
    if payload.get("action") != "completed":
        return f"run not completed ({payload.get('action')})"
    if (payload.get("repository") or {}).get("full_name") != settings.repo:
        return "not the Wall Dash repo"
    if (payload.get("workflow_run") or {}).get("path") != settings.workflow:
        return "not the deploy workflow"
    if not isinstance((payload.get("workflow_run") or {}).get("id"), int):
        return "no run id"
    return None


# --- Deploying ----------------------------------------------------------------


@dataclass
class Result:
    kind: str  # "production" or "preview"
    commit: str
    run_id: int
    run_url: str
    devices: list[str]
    log_index: str | None
    number: int | None = None
    files_written: int = 0
    assets_pruned: int = 0
    integration_changed: bool = False
    previews_removed: list[int] = field(default_factory=list)


def handle_run(
    run_id: int,
    settings: WallDashSettings,
    notify_settings: NotifySettings,
    gh: GitHub | None = None,
    verifier=None,
) -> Result | None:
    """Background task: deploy one finished run, if it's one to deploy."""
    gh = gh or GitHub(settings.github_token or "", settings.repo)
    run: dict = {"id": run_id}
    with _lock, logfire.span("Wall Dash run {run_id}", run_id=run_id):
        try:
            run = gh.run(run_id)
            target = classify(run, settings)
            if isinstance(target, str):
                logfire.info("Not deploying run {run_id}: {reason}", run_id=run_id, reason=target)
                return None
            if isinstance(target, Preview):
                target = _resolve_preview(target, run, gh)
                if target is None:
                    return None
            result = _deploy_run(run, target, settings, gh, verifier)
        except Exception as e:
            logfire.error("Wall Dash deploy failed", _exc_info=True)
            commit = (run.get("head_sha") or "")[:7]
            notify.failure(
                notify_settings,
                f"Wall Dash deploy failed ({commit or f'run {run_id}'})",
                e,
                run.get("html_url"),
            )
            return None

        try:
            result.previews_removed = sweep_previews(settings, gh.open_pull_numbers())
        except Exception:
            logfire.error("Couldn't sweep old Wall Dash previews", _exc_info=True)
        _record(result, settings)
        logfire.info("Deployed Wall Dash {kind} {commit}", kind=result.kind, commit=result.commit[:7])
        if result.kind == "production":
            _tell_home_assistant(result)
        _discord_success(result, settings, notify_settings)
        return result


def _resolve_preview(target: Preview, run: dict, gh: GitHub) -> Preview | None:
    number = target.number
    if number is None:
        owner = gh.repo.split("/")[0]
        number = gh.pull_for_branch(owner, run.get("head_branch") or "")
    if number is None:
        logfire.info("No open PR for run {run_id}", run_id=run.get("id"))
        return None
    pr = gh.pull(number)
    if pr.get("state") != "open":
        logfire.info("PR {number} is closed; not deploying its preview", number=number)
        return None
    return Preview(number=number)


def _deploy_run(
    run: dict, target: Production | Preview, settings: WallDashSettings, gh: GitHub, verifier
) -> Result:
    is_production = isinstance(target, Production)
    dest_root = (
        os.path.dirname(os.path.normpath(settings.www_dir)) if is_production else settings.preview_dir
    )
    os.makedirs(dest_root, exist_ok=True)
    # Unpack beside the target, on the same filesystem, so files move in with a rename
    staging = tempfile.mkdtemp(prefix=".wall-dash-deploy-", dir=dest_root)
    try:
        with gh.download_artifact(run["id"], ARTIFACT_NAME, os.path.join(staging, "a.zip")) as z:
            names = set(z.namelist())
            for needed in (TARBALL_NAME, BUNDLE_NAME):
                if needed not in names:
                    raise RuntimeError(f"artifact has no {needed}")
            tarball, bundle = z.read(TARBALL_NAME), z.read(BUNDLE_NAME)
        os.remove(os.path.join(staging, "a.zip"))

        # Nothing is unpacked until the signature checks out
        verified = provenance.verify(
            tarball,
            bundle,
            provenance.Expected(
                repo=settings.repo,
                workflow=settings.workflow,
                ref=target.ref,
                run_id=run["id"],
                # A PR build checks out GitHub's merge commit, not the head
                commit=run["head_sha"] if is_production else None,
            ),
            verifier=verifier,
        )

        unpacked = os.path.join(staging, "unpacked")
        with tarfile.open(fileobj=io.BytesIO(tarball)) as tar:
            tar.extractall(unpacked, filter="data")
        www = os.path.join(unpacked, "www")
        integration = os.path.join(unpacked, "custom_components", "wall_dash")
        if not os.path.isfile(os.path.join(www, "index.html")):
            raise RuntimeError("artifact has no www/index.html")
        if not os.path.isfile(os.path.join(integration, "manifest.json")):
            raise RuntimeError("artifact has no custom_components/wall_dash/manifest.json")
        _check_version(www, run)
        devices = sorted(
            d for d in os.listdir(www) if os.path.isfile(os.path.join(www, d, "index.html"))
        )

        result = Result(
            kind="production" if is_production else "preview",
            commit=run["head_sha"],
            run_id=run["id"],
            run_url=run.get("html_url") or "",
            devices=devices,
            log_index=verified.log_index,
        )
        if is_production:
            result.files_written = _copy_www(www, settings.www_dir)
            result.assets_pruned = _prune_assets(settings.www_dir, time.time() - ASSET_MAX_AGE)
            result.integration_changed = _swap_integration(integration, settings.integration_dir)
        else:
            result.number = target.number
            _deploy_preview(www, target.number, settings.preview_dir)
            # Says whether the preview is missing an integration change
            result.integration_changed = _tree_hash(integration) != _tree_hash(
                settings.integration_dir
            )
        _keep_bundle(bundle, run, settings)
        return result
    finally:
        shutil.rmtree(staging, ignore_errors=True)


def _check_version(www: str, run: dict) -> None:
    """The build stamps the commit it built into version.json: make sure it's this run's."""
    with open(os.path.join(www, "version.json")) as f:
        version = json.load(f)
    built = version.get("head") or version.get("commit")
    if built != run.get("head_sha"):
        raise RuntimeError(f"artifact is {str(built)[:7]}, run is {run.get('head_sha', '')[:7]}")


def _walk_files(src: str) -> list[str]:
    files = []
    for root, _, names in os.walk(src):
        for name in names:
            files.append(os.path.relpath(os.path.join(root, name), src))
    return files


def _copy_www(src: str, dest: str) -> int:
    """Move src's files over dest's, entry points last. Returns files written."""
    files = sorted(_walk_files(src), key=lambda rel: (os.path.basename(rel) in ENTRY_FILES, rel))
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


def _sync_shared(src: str, dest: str) -> None:
    """Copy src's files into dest where they differ (no deletions)."""
    for rel in _walk_files(src):
        source, target = os.path.join(src, rel), os.path.join(dest, rel)
        if os.path.isfile(target) and filecmp.cmp(source, target, shallow=False):
            continue
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + ".tmp"
        shutil.copyfile(source, tmp)
        os.replace(tmp, target)


def _deploy_preview(www: str, number: int, preview_dir: str) -> None:
    emoji = os.path.join(www, "emoji")
    if os.path.isdir(emoji):
        _sync_shared(emoji, os.path.join(preview_dir, SHARED_EMOJI))
        shutil.rmtree(emoji)
    os.symlink(os.path.join("..", SHARED_EMOJI), emoji)

    target = os.path.join(preview_dir, str(number))
    outgoing = os.path.join(preview_dir, f".{number}.old")
    shutil.rmtree(outgoing, ignore_errors=True)
    if os.path.isdir(target):
        os.rename(target, outgoing)
    os.rename(www, target)
    shutil.rmtree(outgoing, ignore_errors=True)


def remove_preview(number: int, settings: WallDashSettings) -> bool:
    path = os.path.join(settings.preview_dir, str(int(number)))
    if not os.path.isdir(path):
        return False
    shutil.rmtree(path)
    logfire.info("Removed Wall Dash preview {number}", number=number)
    return True


def sweep_previews(settings: WallDashSettings, open_numbers: set[int]) -> list[int]:
    """Remove previews of PRs that aren't open."""
    if not os.path.isdir(settings.preview_dir):
        return []
    removed = []
    for name in os.listdir(settings.preview_dir):
        if name.isdigit() and int(name) not in open_numbers:
            remove_preview(int(name), settings)
            removed.append(int(name))
    return sorted(removed)


# --- Afterwards -----------------------------------------------------------------


def _keep_bundle(bundle: bytes, run: dict, settings: WallDashSettings) -> None:
    try:
        bundles = os.path.join(settings.state_dir, "bundles")
        os.makedirs(bundles, exist_ok=True)
        name = f"{run['id']}-{run.get('run_attempt', 1)}-{run['head_sha'][:7]}.sigstore.json"
        with open(os.path.join(bundles, name), "wb") as f:
            f.write(bundle)
    except OSError:
        logfire.error("Couldn't keep the deploy's Sigstore bundle", _exc_info=True)


def _record(result: Result, settings: WallDashSettings) -> None:
    try:
        os.makedirs(settings.state_dir, exist_ok=True)
        entry = {
            "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "kind": result.kind,
            "pr": result.number,
            "commit": result.commit,
            "run": result.run_url,
            "rekor_log_index": result.log_index,
            "integration_changed": result.integration_changed,
        }
        with open(os.path.join(settings.state_dir, "deploys.jsonl"), "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        logfire.error("Couldn't record the deploy", _exc_info=True)


def _tell_home_assistant(result: Result) -> None:
    """Fire wall_dash_deployed, and ask for a restart if the integration changed.

    Needs `homeassistant_api: true`; outside HA (no SUPERVISOR_TOKEN) it's skipped.
    """
    token = os.getenv("SUPERVISOR_TOKEN")
    if not token:
        return
    try:
        with httpx.Client(
            base_url=SUPERVISOR_CORE_API, headers={"Authorization": f"Bearer {token}"}, timeout=10
        ) as ha:
            ha.post(
                "/events/wall_dash_deployed",
                json={
                    "commit": result.commit,
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
                            f"Deployed `{result.commit[:7]}`, which changes the wall_dash "
                            "integration. Restart Home Assistant to load it."
                        ),
                    },
                ).raise_for_status()
    except Exception:
        logfire.error("Couldn't tell Home Assistant about the deploy", _exc_info=True)


def _discord_success(
    result: Result, settings: WallDashSettings, notify_settings: NotifySettings
) -> None:
    commit = f"[{result.commit[:7]}](https://github.com/{settings.repo}/commit/{result.commit})"
    lines = []
    if result.kind == "production":
        title = "Wall Dash deployed"
        lines += [
            commit,
            f"Devices: {', '.join(result.devices) or 'none'}",
            f"{result.files_written} files written, {result.assets_pruned} old assets pruned",
        ]
        if result.integration_changed:
            lines.append("**Integration changed: restart Home Assistant to load it.**")
    else:
        title = f"Wall Dash preview: PR #{result.number}"
        lines.append(f"{commit} ([PR](https://github.com/{settings.repo}/pull/{result.number}))")
        base = f"{settings.preview_url}/{result.number}"
        lines += [f"- [{d}]({base}/{d}/index.html)" for d in result.devices]
        if result.integration_changed:
            lines.append("The integration differs from what's live; previews don't deploy it.")
    if result.log_index:
        lines.append(
            f"Signed by run [{result.run_id}]({result.run_url}), "
            f"[Rekor {result.log_index}](https://search.sigstore.dev/?logIndex={result.log_index})"
        )
    if result.previews_removed:
        lines.append("Removed previews: " + ", ".join(f"#{n}" for n in result.previews_removed))
    embed = DiscordEmbed(title=title, description="\n".join(lines), color=notify.GREEN)
    if result.run_url:
        embed.set_url(result.run_url)
    notify.discord(notify_settings, embed)
