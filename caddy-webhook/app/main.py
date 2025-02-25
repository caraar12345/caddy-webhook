import hashlib
import hmac
import json
import os
import pprint

import docker
import git
import logfire
from discord_webhook import DiscordEmbed, DiscordWebhook
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

config_path = "/data/options.json"
if os.path.exists(config_path):
    with open(config_path) as config_file:
        config_data = json.load(config_file)

        LOGFIRE_TOKEN = config_data["logfire_token"]
        DISCORD_WEBHOOK_URL = config_data["discord_webhook_url"]
        GITHUB_WEBHOOK_SECRET = config_data["github_webhook_secret"]
        NOTIFY_DISCORD_USER = config_data["notify_discord_user"]
        CADDY_CONTAINER_NAME = config_data["caddy_container_name"]
        GIT_REPO_PATH = config_data["git_repo_path"]
        GIT_SSH_KEY_FILE = config_data["git_ssh_key_file"]
        GIT_SSH_KNOWN_HOSTS_FILE = config_data["git_ssh_known_hosts_file"]
        GIT_REPO_URL = config_data["git_repo_url"]
        GIT_REPO_BRANCH = config_data["git_repo_branch"]

else:
    logfire.info("HA config file not found, using environment variables")
    load_dotenv()

    LOGFIRE_TOKEN = os.getenv("LOGFIRE_TOKEN")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
    GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
    NOTIFY_DISCORD_USER = os.getenv("NOTIFY_DISCORD_USER")
    CADDY_CONTAINER_NAME = os.getenv("CADDY_CONTAINER_NAME")
    GIT_REPO_PATH = os.getenv("GIT_REPO_PATH")
    GIT_SSH_KEY_FILE = os.getenv("GIT_SSH_KEY_FILE")
    GIT_SSH_KNOWN_HOSTS_FILE = os.getenv("GIT_SSH_KNOWN_HOSTS_FILE")
    GIT_REPO_URL = os.getenv("GIT_REPO_URL")
    GIT_REPO_BRANCH = os.getenv("GIT_REPO_BRANCH")

app = FastAPI()
webhook = DiscordWebhook(url=DISCORD_WEBHOOK_URL)

# configure logfire
logfire.configure(token=LOGFIRE_TOKEN)
logfire.instrument_fastapi(app, capture_headers=True)


def send_discord_success(repo: git.Repo, prev_commit: str, new_commit: str):
    logfire.debug(
        "Posting success to Discord...",
        attributes={"new_commit": new_commit, "prev_commit": prev_commit},
    )
    if prev_commit == new_commit:
        logfire.info("No changes detected in Caddy repo")
        return

    prev_commit_short = prev_commit[:7]
    new_commit_short = new_commit[:7]
    commits = list(repo.iter_commits(f"{new_commit}...{prev_commit}~1"))
    new_commit_msg = commits[0].message.splitlines()[0]
    prev_commit_msg = commits[-1].message.splitlines()[0]

    branch = repo.heads.main
    prcu_diff = branch.commit.diff(f"{new_commit}~1")
    num_changed = len(prcu_diff)
    changed_files = []

    newline = "\n"

    for file in prcu_diff:
        if file.a_path == file.b_path:
            changed_files.append(file.a_path)
        else:
            changed_files.append(f"{file.a_path} ==> {file.b_path}")

    description = f"""{num_changed} files changed\n{newline.join(f"- `{file_path}`" for file_path in changed_files)}"""

    embed = DiscordEmbed(
        title=f"<@!{NOTIFY_DISCORD_USER}> - Caddy repo updated",
        description=description,
        color="00ff44",
    )

    embed.add_embed_field(
        name="Current commit",
        value=f"{new_commit_msg} - [{new_commit_short}]({GIT_REPO_URL}/commit/{new_commit})",
        inline=False,
    )

    embed.add_embed_field(
        name="Previous commit",
        value=f"{prev_commit_msg} - [{prev_commit_short}]({GIT_REPO_URL}/commit/{prev_commit})",
        inline=False,
    )

    webhook.add_embed(embed)
    try:
        webhook.execute(remove_embeds=True)
    except Exception:
        logfire.error("Failed to post success to Discord", _exc_info=True)


# Configuration
def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    if not signature_header:
        return False

    expected_signature = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected_signature}", signature_header)


@app.post("/webhook")
async def github_webhook(request: Request, background_tasks: BackgroundTasks):
    # Verify GitHub webhook signature
    payload_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(payload_body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    pprint.pprint(json.loads(payload_body))
    try:
        # Perform git pull on CADDY_REPO_PATH directory
        repo = git.Repo(GIT_REPO_PATH)
        prev_commit = repo.head.commit.hexsha

        ssh_cmd = f"ssh -i {GIT_SSH_KEY_FILE} -o UserKnownHostsFile={GIT_SSH_KNOWN_HOSTS_FILE}"
        with repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd):
            logfire.info("Pulling repo...")
            repo.remotes[GIT_REPO_BRANCH].pull()
            logfire.debug("New commit: " + repo.head.commit.hexsha[:7])

        new_commit = repo.head.commit.hexsha

        background_tasks.add_task(send_discord_success, repo, prev_commit, new_commit)

        success_log = (
            f"Successfully pulled latest changes from GitHub ({new_commit[:7]})"
        )

        if prev_commit != new_commit:
            # Send SIGHUP to the Docker container
            client = docker.from_env()
            container = client.containers.get(CADDY_CONTAINER_NAME)
            container.exec_run(
                ["/config/caddy", "reload", "-c", "/config/Caddyfile"],
                stdout=False,
                stderr=False,
                workdir="/config",
            )
            success_log += " and reloaded Caddy's config"
        else:
            success_log += " but no changes detected in repo"

        logfire.info(success_log)

        return JSONResponse(
            status_code=200,
            content={
                "message": success_log,
                "new_commit": new_commit,
                "prev_commit": prev_commit,
            },
        )
    except Exception as e:
        description = f"""<@!{NOTIFY_DISCORD_USER}> - Error when pulling or reloading.\n```\n{str(e)}\n```"""

        embed = DiscordEmbed(
            title="Repo updated", description=description, color="ff005e"
        )
        webhook.add_embed(embed)
        webhook.execute(remove_embeds=True)
        logfire.error(
            "Failed to pull latest changes from GitHub or reload Caddy's config",
            _exc_info=True,
        )

        return JSONResponse(
            status_code=500,
            content={
                "message": f"Failed to pull latest changes from GitHub or reload Caddy's config: {str(e)}"
            },
        )
