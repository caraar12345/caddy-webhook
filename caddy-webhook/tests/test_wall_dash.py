import io
import json
import os
import tarfile
import time
import zipfile

import httpx
import pytest
from sigstore.errors import VerificationError

from app import provenance, wall_dash
from app.github import GitHub
from tests.conftest import REPO

SHA = "f" * 40
MERGE_SHA = "e" * 40


def make_tarball(commit=SHA, head=None, integration="v1", devices=("echo-show", "kitchen")):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:

        def add(name, data: bytes):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))

        add("www/index.html", b"loader")
        add("www/entry.json", b"{}")
        add("www/emoji/1f600.png", b"png")
        version = {"commit": commit}
        if head:
            version["head"] = head
        add("www/version.json", json.dumps(version).encode())
        for d in devices:
            add(f"www/{d}/index.html", b"loader")
            add(f"www/{d}/assets/index-{commit[:6]}.js", b"js " + commit.encode())
        add("custom_components/wall_dash/manifest.json", b"{}")
        add("custom_components/wall_dash/__init__.py", integration.encode())
    return buf.getvalue()


def make_zip(tarball, bundle=b'{"fake": "bundle"}'):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr(wall_dash.TARBALL_NAME, tarball)
        if bundle is not None:
            z.writestr(wall_dash.BUNDLE_NAME, bundle)
    return buf.getvalue()


def run(**kw):
    base = {
        "id": 99,
        "run_attempt": 1,
        "path": ".github/workflows/deploy.yaml",
        "status": "completed",
        "conclusion": "success",
        "event": "push",
        "head_branch": "main",
        "head_sha": SHA,
        "html_url": "https://github.com/x/runs/99",
        "repository": {"full_name": REPO},
        "head_repository": {"full_name": REPO},
        "pull_requests": [],
    }
    return {**base, **kw}


def pr_run(number=7, **kw):
    return run(
        **{
            "event": "pull_request",
            "head_branch": "feature",
            "pull_requests": [{"number": number, "head": {"sha": SHA}}],
            **kw,
        }
    )


class FakeGitHub:
    """api.github.com, enough for a deploy."""

    def __init__(self, the_run, zip_bytes, open_prs=(7,), pr_state="open"):
        self.run, self.zip, self.open_prs, self.pr_state = the_run, zip_bytes, set(open_prs), pr_state
        self.requests = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        assert request.url.host == "api.github.com"
        assert request.headers["Authorization"] == "Bearer tok"
        path = request.url.path.removeprefix(f"/repos/{REPO}")
        if path == f"/actions/runs/{self.run['id']}":
            return httpx.Response(200, json=self.run)
        if path == f"/actions/runs/{self.run['id']}/artifacts":
            return httpx.Response(
                200, json={"artifacts": [{"id": 5, "name": "wall-dash", "expired": False, "created_at": "x"}]}
            )
        if path == "/actions/artifacts/5/zip":
            return httpx.Response(200, content=self.zip)
        if path == "/pulls":
            if request.url.params.get("head"):
                return httpx.Response(200, json=[{"number": 7}])
            return httpx.Response(200, json=[{"number": n} for n in sorted(self.open_prs)])
        if path.startswith("/pulls/"):
            return httpx.Response(200, json={"number": int(path.split("/")[-1]), "state": self.pr_state})
        return httpx.Response(404)

    def client(self):
        return GitHub("tok", REPO, transport=httpx.MockTransport(self.handler))


@pytest.fixture
def verified(monkeypatch):
    """Stand in for Sigstore, recording what was expected."""
    calls = []

    def fake_verify(artifact, bundle, expected, verifier=None):
        calls.append(expected)
        return provenance.Verified(log_index="4242")

    monkeypatch.setattr(wall_dash.provenance, "verify", fake_verify)
    return calls


# --- classify ---------------------------------------------------------------


def test_classify(wall_dash_settings):
    s = wall_dash_settings
    assert wall_dash.classify(run(), s) == wall_dash.Production(ref="refs/heads/main")
    assert wall_dash.classify(run(event="workflow_dispatch"), s) == wall_dash.Production(ref="refs/heads/main")
    assert wall_dash.classify(pr_run(), s) == wall_dash.Preview(number=7)
    assert wall_dash.classify(pr_run(pull_requests=[]), s) == wall_dash.Preview(number=None)
    for bad in [
        run(conclusion="failure"),
        run(status="in_progress"),
        run(head_branch="feature"),
        run(event="workflow_dispatch", head_branch="feature"),
        run(path=".github/workflows/other.yaml"),
        run(event="schedule"),
        run(repository={"full_name": "x/y"}),
        pr_run(head_repository={"full_name": "fork/home-assistant-wall-dash"}),
    ]:
        assert isinstance(wall_dash.classify(bad, s), str), bad


def test_should_fetch(wall_dash_settings):
    payload = {
        "action": "completed",
        "repository": {"full_name": REPO},
        "workflow_run": {"id": 99, "path": ".github/workflows/deploy.yaml"},
    }
    assert wall_dash.should_fetch("workflow_run", payload, wall_dash_settings) is None
    assert wall_dash.should_fetch("workflow_run", {**payload, "action": "requested"}, wall_dash_settings)
    assert wall_dash.should_fetch("push", payload, wall_dash_settings)
    assert wall_dash.should_fetch(
        "workflow_run", {**payload, "workflow_run": {"id": "99", "path": ".github/workflows/deploy.yaml"}},
        wall_dash_settings,
    )


# --- production -------------------------------------------------------------


def test_production_deploy(wall_dash_settings, no_notify, verified):
    s = wall_dash_settings
    www = s.www_dir
    # Already there: a stale old asset, a recent one, and an old integration file
    os.makedirs(os.path.join(www, "kitchen/assets"))
    for name, age in [("kitchen/assets/old-stale.js", 40), ("kitchen/assets/old-recent.js", 5)]:
        p = os.path.join(www, name)
        open(p, "w").write("x")
        t = time.time() - age * 86400
        os.utime(p, (t, t))
    os.makedirs(s.integration_dir)
    open(os.path.join(s.integration_dir, "deleted.py"), "w").write("gone")

    fake = FakeGitHub(run(), make_zip(make_tarball()))
    result = wall_dash.handle_run(99, s, no_notify, gh=fake.client())

    assert result.kind == "production" and result.devices == ["echo-show", "kitchen"]
    assert verified == [
        provenance.Expected(
            repo=REPO, workflow=".github/workflows/deploy.yaml", ref="refs/heads/main", run_id=99, commit=SHA
        )
    ]
    assert result.assets_pruned == 1 and result.integration_changed
    assert not os.path.exists(os.path.join(www, "kitchen/assets/old-stale.js"))
    assert os.path.exists(os.path.join(www, "kitchen/assets/old-recent.js"))
    assert os.path.exists(os.path.join(www, "echo-show/index.html"))
    assert not os.path.exists(os.path.join(s.integration_dir, "deleted.py"))
    assert os.path.exists(os.path.join(s.state_dir, "bundles/99-1-fffffff.sigstore.json"))
    record = json.loads(open(os.path.join(s.state_dir, "deploys.jsonl")).read().splitlines()[-1])
    assert record["commit"] == SHA and record["rekor_log_index"] == "4242"
    # No staging left beside the target
    assert not [n for n in os.listdir(os.path.dirname(www)) if n.startswith(".")]
    # Every request went to api.github.com with the token (checked in the fake)
    assert fake.requests

    again = wall_dash.handle_run(99, s, no_notify, gh=FakeGitHub(run(), make_zip(make_tarball())).client())
    assert again.files_written == 0 and not again.integration_changed


def test_failed_verification_writes_nothing(wall_dash_settings, no_notify, monkeypatch):
    def reject(*a, **kw):
        raise VerificationError("Certificate's OIDCBuildConfigURI does not match")

    monkeypatch.setattr(wall_dash.provenance, "verify", reject)
    fake = FakeGitHub(run(), make_zip(make_tarball()))
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()) is None
    assert not os.path.exists(os.path.join(wall_dash_settings.www_dir, "index.html"))
    assert not os.path.exists(wall_dash_settings.integration_dir)


def test_missing_bundle_is_refused(wall_dash_settings, no_notify, verified):
    fake = FakeGitHub(run(), make_zip(make_tarball(), bundle=None))
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()) is None
    assert not verified


def test_artifact_from_another_commit_is_refused(wall_dash_settings, no_notify, verified):
    fake = FakeGitHub(run(), make_zip(make_tarball(commit="0" * 40)))
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()) is None
    assert not os.path.exists(os.path.join(wall_dash_settings.www_dir, "index.html"))


def test_ignored_run_downloads_nothing(wall_dash_settings, no_notify, verified):
    fake = FakeGitHub(run(head_branch="feature"), b"")
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()) is None
    assert [r.url.path for r in fake.requests] == [f"/repos/{REPO}/actions/runs/99"]


# --- previews ---------------------------------------------------------------


def test_preview_deploy(wall_dash_settings, no_notify, verified):
    s = wall_dash_settings
    tarball = make_tarball(commit=MERGE_SHA, head=SHA, integration="v2")
    fake = FakeGitHub(pr_run(), make_zip(tarball))
    result = wall_dash.handle_run(99, s, no_notify, gh=fake.client())

    assert result.kind == "preview" and result.number == 7
    assert verified[0].ref == "refs/pull/7/merge" and verified[0].commit is None
    preview = os.path.join(s.preview_dir, "7")
    assert open(os.path.join(preview, "kitchen/index.html")).read() == "loader"
    assert os.path.islink(os.path.join(preview, "emoji"))
    assert open(os.path.join(preview, "emoji/1f600.png")).read() == "png"
    # Production is untouched, and the integration is never deployed from a PR
    assert not os.path.exists(s.www_dir) and not os.path.exists(s.integration_dir)
    assert result.integration_changed  # differs from what's live

    # A new push to the PR replaces the preview whole
    tarball = make_tarball(commit=MERGE_SHA, head=SHA, devices=("kitchen",))
    wall_dash.handle_run(99, s, no_notify, gh=FakeGitHub(pr_run(), make_zip(tarball)).client())
    assert not os.path.exists(os.path.join(preview, "echo-show"))
    assert not [n for n in os.listdir(s.preview_dir) if n.startswith(".")]


def test_preview_found_by_branch(wall_dash_settings, no_notify, verified):
    tarball = make_tarball(commit=MERGE_SHA, head=SHA)
    fake = FakeGitHub(pr_run(pull_requests=[]), make_zip(tarball))
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()).number == 7


def test_closed_pr_gets_no_preview(wall_dash_settings, no_notify, verified):
    fake = FakeGitHub(pr_run(), make_zip(make_tarball(head=SHA)), pr_state="closed")
    assert wall_dash.handle_run(99, wall_dash_settings, no_notify, gh=fake.client()) is None
    assert not os.path.exists(os.path.join(wall_dash_settings.preview_dir, "7"))


def test_previews_are_swept_and_removed(wall_dash_settings, no_notify, verified):
    s = wall_dash_settings
    for n in ("3", "7", "_emoji"):
        os.makedirs(os.path.join(s.preview_dir, n))
    fake = FakeGitHub(run(), make_zip(make_tarball()), open_prs=(7,))
    result = wall_dash.handle_run(99, s, no_notify, gh=fake.client())
    assert result.previews_removed == [3]
    assert sorted(os.listdir(s.preview_dir)) == ["7", "_emoji"]

    assert wall_dash.remove_preview(7, s)
    assert not wall_dash.remove_preview(7, s)
    assert os.listdir(s.preview_dir) == ["_emoji"]
