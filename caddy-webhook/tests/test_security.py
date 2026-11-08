import hashlib
import hmac

from app.security import verify_signature
from app.settings import github_repo_from_url


def sign(secret: str, body: bytes) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def test_good_signature():
    assert verify_signature("k", b"{}", sign("k", b"{}"))


def test_wrong_secret_or_body():
    assert not verify_signature("k", b"{}", sign("other", b"{}"))
    assert not verify_signature("k", b"{ }", sign("k", b"{}"))


def test_missing_or_malformed_header():
    assert not verify_signature("k", b"{}", None)
    assert not verify_signature("k", b"{}", "")
    assert not verify_signature("k", b"{}", sign("k", b"{}").removeprefix("sha256="))


def test_no_secret_fails_closed():
    # An unset secret must not accept a signature made with an empty key
    assert not verify_signature("", b"{}", sign("", b"{}"))


def test_repo_from_url():
    assert github_repo_from_url("https://github.com/a/b") == "a/b"
    assert github_repo_from_url("https://github.com/a/b.git") == "a/b"
    assert github_repo_from_url("git@github.com:a/b.git") == "a/b"
