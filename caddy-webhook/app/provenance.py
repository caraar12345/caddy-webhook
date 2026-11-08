"""Check that a build came from the right GitHub Actions run, by its Sigstore
bundle.

CI signs the tarball keylessly (`sigstore sign`): Fulcio issues a short-lived
certificate carrying the run's GitHub OIDC claims, and the signature is logged
in Rekor. Verifying the bundle against Sigstore's public-good trust root proves
the bytes were signed by that identity; the policy below then pins the
identity to one repo, one workflow file at one ref, and one run.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from cryptography.x509 import Certificate, ExtensionNotFound
from sigstore.errors import VerificationError
from sigstore.hashes import Hashed
from sigstore.models import Bundle
from sigstore.verify import Verifier, policy

GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"


def _der_utf8(raw: bytes) -> str:
    """Decode a DER UTF8String, as Fulcio's v2 extensions are encoded."""
    if len(raw) < 2 or raw[0] != 0x0C:
        raise VerificationError("extension isn't a DER UTF8String")
    length, offset = raw[1], 2
    if length & 0x80:
        n = length & 0x7F
        length, offset = int.from_bytes(raw[2 : 2 + n], "big"), 2 + n
    if offset + length != len(raw):
        raise VerificationError("malformed DER length")
    return raw[offset:].decode()


class RunOf:
    """The certificate's run invocation URI is any attempt of one run.

    A re-run signs again under a new attempt number; the run is what matters.
    """

    oid = policy.OIDCRunInvocationURI.oid

    def __init__(self, repo: str, run_id: int):
        self._prefix = f"https://github.com/{repo}/actions/runs/{run_id}/attempts/"

    def verify(self, cert: Certificate) -> None:
        try:
            ext = cert.extensions.get_extension_for_oid(self.oid).value
        except ExtensionNotFound:
            raise VerificationError("certificate has no run invocation URI")
        value = _der_utf8(ext.value)  # type: ignore[attr-defined]
        attempt = value.removeprefix(self._prefix)
        if attempt == value or not attempt.isdigit():
            raise VerificationError(f"certificate is from run {value}, not {self._prefix}N")


@dataclass(frozen=True)
class Expected:
    repo: str  # owner/name
    workflow: str  # .github/workflows/deploy.yaml
    ref: str  # refs/heads/main, refs/pull/12/merge
    run_id: int
    commit: str | None = None  # the commit the run checked out, when known

    @property
    def workflow_identity(self) -> str:
        return f"https://github.com/{self.repo}/{self.workflow}@{self.ref}"


def policy_for(expected: Expected) -> policy.AllOf:
    children = [
        policy.Identity(identity=expected.workflow_identity),
        policy.OIDCIssuerV2(GITHUB_ACTIONS_ISSUER),
        policy.OIDCBuildConfigURI(expected.workflow_identity),
        policy.OIDCSourceRepositoryURI(f"https://github.com/{expected.repo}"),
        policy.OIDCSourceRepositoryRef(expected.ref),
        RunOf(expected.repo, expected.run_id),
    ]
    if expected.commit:
        children.append(policy.OIDCSourceRepositoryDigest(expected.commit))
    return policy.AllOf(children)


_verifier: Verifier | None = None
_verifier_lock = threading.Lock()


def _production_verifier() -> Verifier:
    # Fetches Sigstore's trust root over TUF, so make it once
    global _verifier
    with _verifier_lock:
        if _verifier is None:
            _verifier = Verifier.production()
        return _verifier


@dataclass(frozen=True)
class Verified:
    log_index: str | None


def verify(
    artifact: bytes | Hashed,
    bundle_json: bytes,
    expected: Expected,
    verifier: Verifier | None = None,
) -> Verified:
    """Raise VerificationError unless the bundle signs artifact (its bytes, or
    its digest) as expected."""
    bundle = Bundle.from_json(bundle_json)
    (verifier or _production_verifier()).verify_artifact(artifact, bundle, policy_for(expected))
    try:
        log_index = str(bundle.log_entry._inner.log_index)
    except Exception:
        log_index = None
    return Verified(log_index=log_index)
