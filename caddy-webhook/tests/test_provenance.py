"""The provenance policy, against certificates shaped like Fulcio's for a
GitHub Actions run. (Signature and log checks are Sigstore's own; these
cover which identity we accept.)"""

import datetime

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sigstore.errors import VerificationError

from app import provenance

REPO = "caraar12345/home-assistant-wall-dash"
WORKFLOW = ".github/workflows/deploy.yaml"
SHA = "a" * 40


def der_utf8(value: str) -> bytes:
    raw = value.encode()
    if len(raw) < 128:
        return bytes([0x0C, len(raw)]) + raw
    n = (len(raw).bit_length() + 7) // 8
    return bytes([0x0C, 0x80 | n]) + len(raw).to_bytes(n, "big") + raw


def oid(n: int) -> x509.ObjectIdentifier:
    return x509.ObjectIdentifier(f"1.3.6.1.4.1.57264.1.{n}")


def fulcio_like(
    ref="refs/heads/main", run="123/attempts/1", sha=SHA, repo=REPO, issuer=provenance.GITHUB_ACTIONS_ISSUER
):
    identity = f"https://github.com/{repo}/{WORKFLOW}@{ref}"
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "sigstore-intermediate")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([]))
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(minutes=10))
        .add_extension(
            x509.SubjectAlternativeName([x509.UniformResourceIdentifier(identity)]), critical=True
        )
        .add_extension(x509.UnrecognizedExtension(oid(1), issuer.encode()), critical=False)
    )
    v2 = {
        8: issuer,
        12: f"https://github.com/{repo}",
        13: sha,
        14: ref,
        18: identity,
        21: f"https://github.com/{repo}/actions/runs/{run}",
    }
    for n, value in v2.items():
        builder = builder.add_extension(x509.UnrecognizedExtension(oid(n), der_utf8(value)), critical=False)
    return builder.sign(key, hashes.SHA256())


def expected(**kw):
    return provenance.Expected(
        **{"repo": REPO, "workflow": WORKFLOW, "ref": "refs/heads/main", "run_id": 123, "commit": SHA, **kw}
    )


def test_matching_production_build_passes():
    provenance.policy_for(expected()).verify(fulcio_like())


def test_any_attempt_of_the_run_passes():
    provenance.policy_for(expected()).verify(fulcio_like(run="123/attempts/3"))


@pytest.mark.parametrize(
    "cert",
    [
        pytest.param(dict(run="124/attempts/1"), id="another run"),
        pytest.param(dict(run="1234/attempts/1"), id="run id prefix"),
        pytest.param(dict(run="123/attempts/1x"), id="junk attempt"),
        pytest.param(dict(ref="refs/heads/feature"), id="another branch"),
        pytest.param(dict(ref="refs/pull/7/merge"), id="a PR build"),
        pytest.param(dict(sha="b" * 40), id="another commit"),
        pytest.param(dict(repo="someone/home-assistant-wall-dash"), id="another repo"),
        pytest.param(dict(issuer="https://accounts.google.com"), id="not GitHub Actions"),
    ],
)
def test_mismatches_fail(cert):
    with pytest.raises(VerificationError):
        provenance.policy_for(expected()).verify(fulcio_like(**cert))


def test_preview_pins_the_pr_ref_not_the_commit():
    pr = expected(ref="refs/pull/7/merge", commit=None)
    provenance.policy_for(pr).verify(fulcio_like(ref="refs/pull/7/merge", sha="c" * 40))
    with pytest.raises(VerificationError):
        provenance.policy_for(pr).verify(fulcio_like(ref="refs/pull/8/merge"))


def test_der_utf8_long_form():
    long = "x" * 300
    assert provenance._der_utf8(der_utf8(long)) == long
    with pytest.raises(VerificationError):
        provenance._der_utf8(b"\x04\x01x")
