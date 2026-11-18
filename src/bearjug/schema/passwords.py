"""Attacker-supplied passwords outside raw evidence.

Normalised events and intelligence never carry a plaintext password. They carry
a :class:`PasswordRef`: an HMAC-SHA256 of the password under a collector-held
key (so the same password links sessions together without being readable or
brute-forceable from the hash alone), plus coarse features for analysis.

Hashes are only comparable when they share a ``key_id``. Rotating the key
starts a new correlation space.
"""

from __future__ import annotations

import hashlib
import hmac
import string

from pydantic import Field

from .common import Identifier, Model, Sha256

MIN_KEY_BYTES = 32


class PasswordFeatures(Model):
    length: int = Field(ge=0)
    has_lower: bool
    has_upper: bool
    has_digit: bool
    has_symbol: bool
    in_wordlist: bool | None = None
    """Whether the password appears in a known wordlist; None if not checked."""


class PasswordRef(Model):
    key_id: Identifier
    hmac_sha256: Sha256
    features: PasswordFeatures


def password_ref(
    password: str,
    *,
    key: bytes,
    key_id: str,
    wordlist: frozenset[str] | set[str] | None = None,
) -> PasswordRef:
    """Build the keyed-hash reference for a password.

    ``key`` is a secret held by the collector, at least 32 bytes. It must never
    be shipped to sensors or stored alongside events.
    """
    if len(key) < MIN_KEY_BYTES:
        raise ValueError(f"password hashing key must be at least {MIN_KEY_BYTES} bytes")
    digest = hmac.new(key, password.encode("utf-8", "surrogatepass"), hashlib.sha256).hexdigest()
    features = PasswordFeatures(
        length=len(password),
        has_lower=any(c.islower() for c in password),
        has_upper=any(c.isupper() for c in password),
        has_digit=any(c in string.digits for c in password),
        has_symbol=any(not c.isalnum() for c in password),
        in_wordlist=None if wordlist is None else password in wordlist,
    )
    return PasswordRef(key_id=key_id, hmac_sha256=digest, features=features)
