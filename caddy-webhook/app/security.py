"""GitHub webhook signatures."""

from __future__ import annotations

import hashlib
import hmac


def verify_signature(secret: str, payload_body: bytes, signature_header: str | None) -> bool:
    """Check GitHub's X-Hub-Signature-256 header. Fails closed without a secret."""
    if not secret or not signature_header or not signature_header.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature_header)
