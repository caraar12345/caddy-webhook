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
from fastapi import FastAPI, HTTPException, Request
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

else:
    logfire.info("Config file not found, using environment variables")
    load_dotenv()

    LOGFIRE_TOKEN = os.getenv("LOGFIRE_TOKEN")
    DISCORD_WEBHOOK_URL = os.getenv("DISCORD_WEBHOOK_URL")
    GITHUB_WEBHOOK_SECRET = os.getenv("GITHUB_WEBHOOK_SECRET")
    NOTIFY_DISCORD_USER = os.getenv("NOTIFY_DISCORD_USER")
    CADDY_CONTAINER_NAME = os.getenv("CADDY_CONTAINER_NAME")

app = FastAPI()
webhook = DiscordWebhook(url=DISCORD_WEBHOOK_URL)

# configure logfire
logfire.configure(token=LOGFIRE_TOKEN)
logfire.instrument_fastapi(app, capture_headers=True)


# Configuration
def verify_signature(payload_body: bytes, signature_header: str) -> bool:
    if not signature_header:
        return False

    expected_signature = hmac.new(
        GITHUB_WEBHOOK_SECRET.encode(), payload_body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(f"sha256={expected_signature}", signature_header)


@app.post("/webhook")
async def github_webhook(request: Request):
    # Verify GitHub webhook signature
    payload_body = await request.body()
    signature = request.headers.get("X-Hub-Signature-256")
    if not verify_signature(payload_body, signature):
        raise HTTPException(status_code=401, detail="Invalid signature")
    pprint.pprint(json.loads(payload_body))
    try:
        # Perform git pull on /share/caddy directory
        repo = git.Repo("/share/caddy")
        ssh_cmd = 'ssh -i /ssl/.ssh/id_ed25519 -o UserKnownHostsFile=/ssl/.ssh/github.com.hostkey'
        with repo.git.custom_environment(GIT_SSH_COMMAND=ssh_cmd):
            logfire.info("Pulling repo...")
            logfire.debug(str(repo.remotes["main"].pull()))

        main_branch = repo.heads.main

        # Send SIGHUP to the Docker container
        client = docker.from_env()
        container = client.containers.get(CADDY_CONTAINER_NAME)
        container.kill(signal="SIGHUP")

        main_branch_log = main_branch.log()

        previous_commit = main_branch_log[-2][1]
        pc_message = main_branch_log[-2][4].split(": ")[1]
        current_commit = main_branch_log[-1][1]
        cc_message = main_branch_log[-1][4].split(": ")[1]

        prev_commit_short = previous_commit[:7]
        cur_commit_short = current_commit[:7]

        prcu_diff = main_branch.commit.diff("HEAD~1")
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
            title="Caddy repo updated", description=description, color="00ff44"
        )

        embed.add_embed_field(
            name="Current commit",
            value=f"{cc_message} - [{cur_commit_short}](https://github.com/caraar12345/infra-caddy/commit/{current_commit})",
            inline=False,
        )

        embed.add_embed_field(
            name="Previous commit",
            value=f"{pc_message} - [{prev_commit_short}](https://github.com/caraar12345/infra-caddy/commit/{previous_commit})",
            inline=False,
        )

        webhook.add_embed(embed)
        webhook.execute()

        logfire.info(
            f"Successfully pulled latest changes from GitHub ({prev_commit_short}) and sent SIGHUP to container"
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": f"Successfully pulled latest changes from GitHub ({prev_commit_short}) and sent SIGHUP to container"
            },
        )
    except Exception as e:
        description = (
            f"""<@!{NOTIFY_DISCORD_USER}> - Invalid Caddyfile.\n```\n{str(e)}\n```"""
        )

        embed = DiscordEmbed(
            title="Caddy repo updated", description=description, color="ff005e"
        )
        webhook.add_embed(embed)
        webhook.execute()
        logfire.error(
            f"Failed to pull latest changes from GitHub or send SIGHUP to container: {str(e)}"
        )

        return JSONResponse(
            status_code=500,
            content={
                "message": f"Failed to pull latest changes from GitHub or send SIGHUP to container: {str(e)}"
            },
        )
