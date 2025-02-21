import hashlib
import hmac

import docker
import dotenv
import git
import logfire
from discord_webhook import DiscordEmbed, DiscordWebhook
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse

GITHUB_REPO = "caraar12345/infra-caddy"
GITHUB_BRANCH = "main"
GITHUB_WEBHOOK_SECRET = dotenv.get_key(".env", "GITHUB_WEBHOOK_SECRET")

# create a fastapi app, see https://fastapi.tiangolo.com/reference/fastapi/
app = FastAPI()
webhook = DiscordWebhook(url=dotenv.get_key(".env", "DISCORD_WEBHOOK_URL"))

# configure logfire
logfire.configure(token=dotenv.get_key(".env", "LOGFIRE_TOKEN"))
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

    try:
        # Perform git pull on /share/caddy directory
        repo = git.Repo("/share/caddy")
        with repo.git.custom_environment(
            GIT_SSH_COMMAND="ssh -i /ssl/.ssh/id_ed25519 -o UserKnownHostsFile=/ssl/.ssh/github.com.hostkey"
        ):
            origin = repo.remotes.origin
            origin.pull()

        main_branch = repo.heads.main

        # Send SIGHUP to the Docker container
        client = docker.from_env()
        container = client.containers.get("d630ad5e_caddy-2")
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
            "Successfully pulled latest changes from GitHub ({prev_commit_short}) and sent SIGHUP to container"
        )

        return JSONResponse(
            status_code=200,
            content={
                "message": "Successfully pulled latest changes from GitHub ({prev_commit_short}) and sent SIGHUP to container"
            },
        )
    except Exception as e:
        description += f"""<@!{dotenv.get_key(".env", "NOTIFY_DISCORD_USER")}> - Invalid Caddyfile.\n```\n{str(e)}\n```"""
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
