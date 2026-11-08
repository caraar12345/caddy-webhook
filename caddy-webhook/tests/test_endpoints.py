import importlib
import json
import os

import pytest
from fastapi.testclient import TestClient

from tests.conftest import REPO, SECRET
from tests.test_security import sign

WALL_DASH_SECRET = "wd-secret"


@pytest.fixture(scope="module")
def main(tmp_path_factory):
    env = {
        "GITHUB_WEBHOOK_SECRET": SECRET,
        "WALL_DASH_WEBHOOK_SECRET": WALL_DASH_SECRET,
        "WALL_DASH_GITHUB_TOKEN": "tok",
        "CADDY_CONTAINER_NAME": "caddy",
        "GIT_REPO_PATH": str(tmp_path_factory.mktemp("not-a-repo")),
        "GIT_REPO_URL": "https://github.com/caraar12345/infra-caddy",
        "WALL_DASH_PREVIEW_DIR": str(tmp_path_factory.mktemp("previews")),
    }
    old = {k: os.environ.get(k) for k in env}
    os.environ.update(env)
    try:
        import app.main

        yield importlib.reload(app.main)
    finally:
        for k, v in old.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v


@pytest.fixture
def client(main):
    return TestClient(main.app)


def post(client, path, event, payload, secret):
    body = json.dumps(payload).encode()
    headers = {"X-GitHub-Event": event, "X-Hub-Signature-256": sign(secret, body)}
    return client.post(path, content=body, headers=headers)


def test_docs_are_off(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_bad_signatures(client):
    for path in ("/webhook", "/webhook/wall-dash"):
        r = client.post(path, content=b"{}", headers={"X-GitHub-Event": "ping"})
        assert r.status_code == 401
    # Each endpoint takes only its own secret
    assert post(client, "/webhook", "ping", {}, WALL_DASH_SECRET).status_code == 401
    assert post(client, "/webhook/wall-dash", "ping", {}, SECRET).status_code == 401


def test_ping(client):
    assert post(client, "/webhook", "ping", {}, SECRET).json() == {"message": "pong"}
    assert post(client, "/webhook/wall-dash", "ping", {}, WALL_DASH_SECRET).json() == {"message": "pong"}


def test_caddy_ignores_other_events(client, main, monkeypatch):
    monkeypatch.setattr(main, "_deploy_caddy", lambda: pytest.fail("should not deploy"))
    push = {"ref": "refs/heads/main", "repository": {"full_name": "caraar12345/infra-caddy"}}
    for event, payload in [
        ("workflow_run", push),
        ("push", {**push, "ref": "refs/heads/other"}),
        ("push", {**push, "repository": {"full_name": REPO}}),
    ]:
        r = post(client, "/webhook", event, payload, SECRET)
        assert r.status_code == 200 and r.json()["message"].startswith("Ignored"), r.json()


def test_caddy_deploys_push(client, main, monkeypatch):
    from fastapi.responses import JSONResponse

    monkeypatch.setattr(main, "_deploy_caddy", lambda: JSONResponse({"message": "deployed"}))
    push = {"ref": "refs/heads/main", "repository": {"full_name": "caraar12345/infra-caddy"}}
    assert post(client, "/webhook", "push", push, SECRET).json() == {"message": "deployed"}


def test_caddy_errors_stay_vague(client, main, monkeypatch):
    def explode(settings, reload):
        raise RuntimeError("/share/caddy: secret path details")

    monkeypatch.setattr(main.caddy, "deploy", explode)
    monkeypatch.setattr(main.notify, "failure", lambda *a, **kw: None)
    push = {"ref": "refs/heads/main", "repository": {"full_name": "caraar12345/infra-caddy"}}
    r = post(client, "/webhook", "push", push, SECRET)
    assert r.status_code == 500 and "share" not in r.text


def test_wall_dash_run_is_checked_in_background(client, main, monkeypatch):
    seen = []
    monkeypatch.setattr(main.wall_dash, "handle_run", lambda run_id, *a: seen.append(run_id))
    payload = {
        "action": "completed",
        "repository": {"full_name": REPO},
        "workflow_run": {"id": 99, "path": ".github/workflows/deploy.yaml", "artifacts_url": "https://evil"},
    }
    r = post(client, "/webhook/wall-dash", "workflow_run", payload, WALL_DASH_SECRET)
    assert r.status_code == 202 and seen == [99]

    r = post(client, "/webhook/wall-dash", "workflow_run", {**payload, "action": "requested"}, WALL_DASH_SECRET)
    assert r.json()["message"].startswith("Ignored") and seen == [99]


def test_wall_dash_closed_pr_removes_preview(client, main, monkeypatch):
    removed = []
    monkeypatch.setattr(main.wall_dash, "remove_preview", lambda n, s: removed.append(n))
    pr = {"action": "closed", "pull_request": {"number": 7}, "repository": {"full_name": REPO}}
    assert post(client, "/webhook/wall-dash", "pull_request", pr, WALL_DASH_SECRET).status_code == 202
    post(client, "/webhook/wall-dash", "pull_request", {**pr, "action": "opened"}, WALL_DASH_SECRET)
    post(client, "/webhook/wall-dash", "pull_request", {**pr, "pull_request": {"number": "7/../x"}}, WALL_DASH_SECRET)
    assert removed == [7]
