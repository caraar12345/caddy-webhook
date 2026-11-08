import pytest

from app import caddy
from tests.conftest import git

PUSH = {"ref": "refs/heads/main", "repository": {"full_name": "caraar12345/infra-caddy"}}


def push(upstream, content, message="change"):
    (upstream / "Caddyfile").write_text(content)
    git(upstream, "commit", "-q", "-am", message)
    git(upstream, "push", "-q", "origin", "main")
    return git(upstream, "rev-parse", "HEAD")


class Reloads:
    def __init__(self, fail=False):
        self.calls, self.fail = 0, fail

    def __call__(self):
        self.calls += 1
        if self.fail:
            raise RuntimeError("Error: adapting config: bad directive")


def test_should_deploy(caddy_repos):
    _, _, settings = caddy_repos
    assert caddy.should_deploy("push", PUSH, settings) is None
    assert caddy.should_deploy("ping", PUSH, settings)
    assert caddy.should_deploy("workflow_run", PUSH, settings)
    assert caddy.should_deploy("push", {**PUSH, "ref": "refs/heads/feature"}, settings)
    assert caddy.should_deploy("push", {**PUSH, "repository": {"full_name": "x/wall-dash"}}, settings)


def test_fast_forward_reloads_and_writes_version(caddy_repos):
    upstream, checkout, settings = caddy_repos
    new = push(upstream, "two\n", "Two {braces}")
    reload = Reloads()
    outcome = caddy.deploy(settings, reload)
    assert outcome.changed and outcome.new_commit == new
    assert reload.calls == 1
    assert (checkout / "Caddyfile").read_text() == "two\n"
    snippet = (checkout / "snippets/generated/config_version.caddy").read_text()
    assert new in snippet and "Two (braces)" in snippet


def test_no_change_doesnt_reload(caddy_repos):
    _, _, settings = caddy_repos
    reload = Reloads()
    assert not caddy.deploy(settings, reload).changed
    assert reload.calls == 0


def test_rewritten_history_is_refused(caddy_repos):
    upstream, checkout, settings = caddy_repos
    push(upstream, "two\n")
    caddy.deploy(settings, Reloads())
    deployed = git(checkout, "rev-parse", "HEAD")
    # Force-push a branch that doesn't contain the deployed commit
    git(upstream, "reset", "-q", "--hard", "HEAD~1")
    (upstream / "Caddyfile").write_text("evil\n")
    git(upstream, "commit", "-q", "-am", "rewrite")
    git(upstream, "push", "-q", "-f", "origin", "main")

    reload = Reloads()
    with pytest.raises(caddy.Refused):
        caddy.deploy(settings, reload)
    assert reload.calls == 0
    assert git(checkout, "rev-parse", "HEAD") == deployed
    assert (checkout / "Caddyfile").read_text() == "two\n"


def test_failed_reload_rolls_back(caddy_repos):
    upstream, checkout, settings = caddy_repos
    before = git(checkout, "rev-parse", "HEAD")
    push(upstream, "broken\n")
    with pytest.raises(caddy.ReloadFailed, match="Rolled the checkout back"):
        caddy.deploy(settings, Reloads(fail=True))
    assert git(checkout, "rev-parse", "HEAD") == before
    assert (checkout / "Caddyfile").read_text() == "one\n"
    assert before in (checkout / "snippets/generated/config_version.caddy").read_text()

    # The fix on top of the broken commit still fast-forwards
    fixed = push(upstream, "fixed\n")
    assert caddy.deploy(settings, Reloads()).new_commit == fixed


def test_ignores_payload_commit(caddy_repos):
    """Whatever a delivery claims, the deployed commit is the branch's head."""
    upstream, _, settings = caddy_repos
    head = push(upstream, "two\n")
    assert caddy.deploy(settings, Reloads()).new_commit == head


def test_ssh_command_is_strict(caddy_repos):
    _, _, settings = caddy_repos
    from dataclasses import replace

    env = caddy._git_env(replace(settings, ssh_key_file="/ssl/key file", ssh_known_hosts_file="/ssl/kh"))
    assert "StrictHostKeyChecking=yes" in env["GIT_SSH_COMMAND"]
    assert "'/ssl/key file'" in env["GIT_SSH_COMMAND"]
    assert env["GIT_TERMINAL_PROMPT"] == "0"
