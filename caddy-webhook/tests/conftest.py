import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.settings import CaddySettings, NotifySettings, WallDashSettings  # noqa: E402

SECRET = "s3cret"
REPO = "caraar12345/home-assistant-wall-dash"


def git(cwd, *args):
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "GIT_AUTHOR_NAME": "t",
            "GIT_AUTHOR_EMAIL": "t@example.com",
            "GIT_COMMITTER_NAME": "t",
            "GIT_COMMITTER_EMAIL": "t@example.com",
        },
    ).stdout.strip()


@pytest.fixture
def caddy_repos(tmp_path):
    """An 'upstream' work repo, a bare remote, and the deployed checkout."""
    upstream, remote, checkout = tmp_path / "upstream", tmp_path / "remote.git", tmp_path / "checkout"
    upstream.mkdir()
    git(upstream, "init", "-q", "-b", "main")
    (upstream / "Caddyfile").write_text("one\n")
    git(upstream, "add", ".")
    git(upstream, "commit", "-q", "-m", "first")
    git(tmp_path, "clone", "-q", "--bare", str(upstream), str(remote))
    git(upstream, "remote", "add", "origin", str(remote))
    git(tmp_path, "clone", "-q", str(remote), str(checkout))
    settings = CaddySettings(
        webhook_secret=SECRET,
        container_name="caddy",
        repo_path=str(checkout),
        repo_url="https://github.com/caraar12345/infra-caddy",
        branch="main",
        ssh_key_file=None,
        ssh_known_hosts_file=None,
    )
    return upstream, checkout, settings


@pytest.fixture
def wall_dash_settings(tmp_path):
    return WallDashSettings(
        webhook_secret=SECRET,
        github_token="tok",
        repo=REPO,
        branch="main",
        workflow=".github/workflows/deploy.yaml",
        www_dir=str(tmp_path / "homeassistant/www/wall-dash"),
        integration_dir=str(tmp_path / "homeassistant/custom_components/wall_dash"),
        preview_dir=str(tmp_path / "share/wall-dash/pr"),
        preview_url="https://hass.example/wall-dash/pr",
        state_dir=str(tmp_path / "data/wall-dash"),
    )


@pytest.fixture
def no_notify():
    return NotifySettings(discord_webhook_url=None, discord_user=None)
