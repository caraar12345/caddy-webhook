"""The add-on's options: /data/options.json under Home Assistant, else the
environment (upper-cased option names, or a .env file) for local runs."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from dotenv import load_dotenv

OPTIONS_PATH = "/data/options.json"


def load_options(path: str = OPTIONS_PATH) -> dict:
    if os.path.exists(path):
        with open(path) as f:
            return json.load(f)
    load_dotenv()
    return {}


class Options:
    def __init__(self, options: dict):
        self._options = options

    def get(self, key: str, default: str | None = None) -> str | None:
        value = self._options.get(key)
        if value is None:
            value = os.getenv(key.upper())
        if value is None or value == "":
            return default
        return str(value)

    def require(self, key: str) -> str:
        value = self.get(key)
        if not value:
            raise RuntimeError(f"The {key} option must be set")
        return value


def github_repo_from_url(url: str) -> str:
    """'https://github.com/owner/repo(.git)' or 'git@github.com:owner/repo.git' -> 'owner/repo'."""
    path = url.split("github.com", 1)[-1].lstrip(":/")
    return path.removesuffix(".git").strip("/")


@dataclass(frozen=True)
class CaddySettings:
    webhook_secret: str
    container_name: str
    repo_path: str
    repo_url: str
    branch: str
    ssh_key_file: str | None
    ssh_known_hosts_file: str | None

    @property
    def repo(self) -> str:
        return github_repo_from_url(self.repo_url)

    @classmethod
    def load(cls, options: Options) -> CaddySettings:
        return cls(
            webhook_secret=options.require("github_webhook_secret"),
            container_name=options.require("caddy_container_name"),
            repo_path=options.require("git_repo_path"),
            repo_url=options.require("git_repo_url"),
            branch=options.get("git_repo_branch", "main"),
            ssh_key_file=options.get("git_ssh_key_file"),
            ssh_known_hosts_file=options.get("git_ssh_known_hosts_file"),
        )


@dataclass(frozen=True)
class WallDashSettings:
    webhook_secret: str
    github_token: str | None
    repo: str
    branch: str
    workflow: str
    www_dir: str
    integration_dir: str
    preview_dir: str
    preview_url: str
    state_dir: str

    @classmethod
    def load(cls, options: Options) -> WallDashSettings:
        return cls(
            # Its own secret if set, so a leak of one doesn't open the other
            webhook_secret=options.get("wall_dash_webhook_secret")
            or options.require("github_webhook_secret"),
            github_token=options.get("wall_dash_github_token"),
            repo=options.get("wall_dash_repo", "caraar12345/home-assistant-wall-dash"),
            branch=options.get("wall_dash_branch", "main"),
            workflow=options.get("wall_dash_workflow", ".github/workflows/deploy.yaml"),
            www_dir=options.get("wall_dash_www_dir", "/homeassistant/www/wall-dash"),
            integration_dir=options.get(
                "wall_dash_integration_dir", "/homeassistant/custom_components/wall_dash"
            ),
            preview_dir=options.get("wall_dash_preview_dir", "/share/wall-dash/pr"),
            preview_url=options.get(
                "wall_dash_preview_url", "https://hass-new.adhd.energy/wall-dash/pr"
            ).rstrip("/"),
            state_dir=options.get("wall_dash_state_dir", "/data/wall-dash"),
        )


@dataclass(frozen=True)
class NotifySettings:
    discord_webhook_url: str | None
    discord_user: str | None

    @classmethod
    def load(cls, options: Options) -> NotifySettings:
        return cls(
            discord_webhook_url=options.get("discord_webhook_url"),
            discord_user=options.get("notify_discord_user"),
        )
