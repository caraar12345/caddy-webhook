"""caddy-webhook: GitHub webhooks for the homelab.

- POST /webhook: infra-caddy pushes -> fast-forward /share/caddy, reload Caddy
- POST /webhook/wall-dash: Wall Dash builds -> verify provenance, deploy

Both check GitHub's HMAC signature first; nothing else is served.
"""

from __future__ import annotations

import json

import git
import logfire
from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app import caddy, notify, wall_dash
from app.security import verify_signature
from app.settings import (
    CaddySettings,
    NotifySettings,
    Options,
    WallDashSettings,
    load_options,
)

options = Options(load_options())
CADDY = CaddySettings.load(options)
WALL_DASH = WallDashSettings.load(options)
NOTIFY = NotifySettings.load(options)

# No /docs, /redoc or /openapi.json: this is reachable from the internet
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

logfire.configure(token=options.get("logfire_token"), send_to_logfire="if-token-present")
logfire.instrument_fastapi(app, capture_headers=True)

# Keep the snippet in step with the checkout so a Caddy restart also picks it up
try:
    caddy.write_version_snippet(CADDY, git.Repo(CADDY.repo_path).head.commit)
except Exception:
    logfire.error("Failed to write Caddy version snippet", _exc_info=True)


async def _signed_payload(request: Request, secret: str) -> tuple[str | None, dict]:
    body = await request.body()
    if not verify_signature(secret, body, request.headers.get("X-Hub-Signature-256")):
        raise HTTPException(status_code=401, detail="Invalid signature")
    try:
        payload = json.loads(body)
    except ValueError:
        raise HTTPException(status_code=400, detail="Body isn't JSON")
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Body isn't a JSON object")
    event = request.headers.get("X-GitHub-Event")
    logfire.info(
        "GitHub {event} delivery {delivery}",
        event=event,
        delivery=request.headers.get("X-GitHub-Delivery"),
    )
    return event, payload


@app.post("/webhook")
async def caddy_webhook(request: Request):
    event, payload = await _signed_payload(request, CADDY.webhook_secret)
    if event == "ping":
        return {"message": "pong"}
    ignored = caddy.should_deploy(event, payload, CADDY)
    if ignored:
        logfire.info("Ignoring Caddy webhook: {reason}", reason=ignored)
        return {"message": f"Ignored: {ignored}"}
    # Blocking git and docker work: run it off the event loop
    return await run_in_threadpool(_deploy_caddy)


def _deploy_caddy() -> JSONResponse:
    try:
        outcome = caddy.deploy(CADDY, caddy.docker_reloader(CADDY))
    except caddy.Refused as e:
        logfire.error("Refused to deploy Caddy config: {reason}", reason=str(e))
        notify.failure(NOTIFY, "Caddy repo update refused", e)
        return JSONResponse(status_code=409, content={"message": "Refused; see Discord"})
    except Exception as e:
        logfire.error("Failed to update or reload Caddy's config", _exc_info=True)
        notify.failure(NOTIFY, "Caddy repo update failed", e)
        # Details go to Discord and logfire, not back over the internet
        return JSONResponse(status_code=500, content={"message": "Failed; see Discord"})

    if outcome.changed:
        message = f"Deployed {outcome.new_commit[:7]} and reloaded Caddy"
        try:
            caddy.notify_success(outcome, CADDY, NOTIFY)
        except Exception:
            logfire.error("Failed to post success to Discord", _exc_info=True)
    else:
        message = f"Already at {outcome.new_commit[:7]}"
    logfire.info(message)
    return JSONResponse(
        status_code=200,
        content={"message": message, "new_commit": outcome.new_commit, "prev_commit": outcome.prev_commit},
    )


@app.post("/webhook/wall-dash")
async def wall_dash_webhook(request: Request, background_tasks: BackgroundTasks):
    """Workflow runs and pull requests from home-assistant-wall-dash."""
    event, payload = await _signed_payload(request, WALL_DASH.webhook_secret)
    if event == "ping":
        return {"message": "pong"}
    if not WALL_DASH.github_token:
        raise HTTPException(status_code=503, detail="wall_dash_github_token isn't set")

    if event == "pull_request":
        number = (payload.get("pull_request") or {}).get("number")
        if (
            payload.get("action") == "closed"
            and isinstance(number, int)
            and (payload.get("repository") or {}).get("full_name") == WALL_DASH.repo
        ):
            background_tasks.add_task(wall_dash.remove_preview, number, WALL_DASH)
            return JSONResponse(status_code=202, content={"message": f"Removing preview {number}"})
        return {"message": "Ignored: only closed PRs matter"}

    ignored = wall_dash.should_fetch(event, payload, WALL_DASH)
    if ignored:
        logfire.info("Ignoring Wall Dash webhook: {reason}", reason=ignored)
        return {"message": f"Ignored: {ignored}"}

    run_id = payload["workflow_run"]["id"]
    # GitHub gives up after 10 s; the outcome goes to Discord and logfire
    background_tasks.add_task(wall_dash.handle_run, run_id, WALL_DASH, NOTIFY)
    return JSONResponse(status_code=202, content={"message": "Checking run", "run_id": run_id})
