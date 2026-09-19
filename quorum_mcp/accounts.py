#!/usr/bin/env python3
"""
quorum_mcp.accounts -- per-account Telinea key custody.

A user passes their Telinea API key to Quorum once, at account setup
(the register tool). Quorum stores it encrypted in the account record
and uses it to authenticate every span pushed for that account's
proposals -- standard OTLP bearer auth against the ingest endpoint.

Envelope encryption, AES-256-GCM:

    KEK  = HKDF-SHA256(quorum_api_key, salt)     -- never stored
    blob = AES-256-GCM(KEK, telinea_api_key)     -- stored

The account record holds account_id (sha256 of the Quorum key, for
lookup), the salt, and the blob. The Quorum API key itself is never
stored in any form -- a database dump yields ciphertext that is
unreadable without it.

Span-time access: votes and writes arrive from agents that do NOT hold
the orchestrator's Quorum key, so the plaintext Telinea key cannot be
re-derived per event. Two access paths, in order:

    1. In-memory cache populated at propose time (the common case).
    2. A proposal-scoped re-encryption under the server data key
       (QUORUM_DATA_KEY env var) stored in the proposal config, which
       survives restarts. The data key lives in the environment, not
       the database -- a DB dump still exposes nothing.

Requires the ``cryptography`` package (same library Terradev uses for
its credential bridge).
"""

import base64
import hashlib
import json
import os
import secrets
import time

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    _HAS_CRYPTO = True
except ImportError:  # pragma: no cover
    _HAS_CRYPTO = False

ACCOUNTS_FILE = os.environ.get(
    "QUORUM_ACCOUNTS",
    os.path.expanduser("~/.quorum/accounts.json"))

# Server-held data key for proposal-scoped re-encryption. Hex or
# passphrase; either is stretched to 32 bytes with sha256. Unset ->
# proposal blobs can't be written; the in-memory cache still works
# until restart.
_DATA_KEY = os.environ.get("QUORUM_DATA_KEY", "").strip()

_HKDF_INFO = b"quorum-mcp/telinea-key-v1"
_HKDF_INFO_DATA = b"quorum-mcp/data-key-v1"

# proposal_id -> plaintext telinea key (populated at propose time)
_key_cache = {}


def available():
    return _HAS_CRYPTO


def account_id_for(quorum_key):
    """The lookup id: sha256 of the Quorum key. Not reversible."""
    return hashlib.sha256(quorum_key.encode()).hexdigest()[:32]


def _kek(quorum_key, salt):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=_HKDF_INFO).derive(quorum_key.encode())


def _data_key():
    if not _DATA_KEY:
        return None
    raw = bytes.fromhex(_DATA_KEY) if all(
        c in "0123456789abcdefABCDEF" for c in _DATA_KEY) \
        and len(_DATA_KEY) == 64 else _DATA_KEY.encode()
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=_HKDF_INFO_DATA).derive(raw)


def _seal(key_bytes, plaintext):
    nonce = secrets.token_bytes(12)
    ct = AESGCM(key_bytes).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + ct).decode()


def _open(key_bytes, blob_b64):
    raw = base64.b64decode(blob_b64)
    return AESGCM(key_bytes).decrypt(raw[:12], raw[12:], None).decode()


def _load_accounts():
    try:
        with open(ACCOUNTS_FILE) as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}


def _save_accounts(accounts):
    os.makedirs(os.path.dirname(ACCOUNTS_FILE), exist_ok=True)
    tmp = ACCOUNTS_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(accounts, f, indent=2)
    os.replace(tmp, ACCOUNTS_FILE)  # atomic


def register(quorum_key, telinea_key):
    """Create or replace an account. Returns the account_id.

    The Quorum key is used to derive the KEK and is then discarded --
    only its sha256 (as account_id) and the encrypted blob persist.
    """
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography package is not installed")
    salt = secrets.token_bytes(16)
    blob = _seal(_kek(quorum_key, salt), telinea_key)
    account_id = account_id_for(quorum_key)
    accounts = _load_accounts()
    accounts[account_id] = {
        "salt": base64.b64encode(salt).decode(),
        "telinea_key_enc": blob,
        "created_at": time.time(),
    }
    _save_accounts(accounts)
    return account_id


def unlock(quorum_key):
    """Resolve a Quorum key -> (account_id, telinea_key) or None.

    Wrong or unregistered keys fail the GCM tag check and return None --
    no oracle on whether the account exists vs. the key was wrong.
    """
    if not _HAS_CRYPTO:
        return None
    account_id = account_id_for(quorum_key)
    rec = _load_accounts().get(account_id)
    if rec is None:
        return None
    try:
        salt = base64.b64decode(rec["salt"])
        return account_id, _open(_kek(quorum_key, salt),
                                 rec["telinea_key_enc"])
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Proposal-scoped access: how spans authenticate after the orchestrator's
# Quorum key is gone from the request path.
# ---------------------------------------------------------------------------

def cache_key(proposal_id, telinea_key):
    _key_cache[proposal_id] = telinea_key


def seal_for_proposal(telinea_key):
    """Re-encrypt a Telinea key under the server data key for storage in
    the proposal config. Returns the blob, or None if no data key."""
    dk = _data_key()
    return _seal(dk, telinea_key) if dk else None


def resolve_key(proposal_id, proposal_blob):
    """The Telinea key for a proposal: memory cache, then the
    proposal-scoped blob under the server data key. None if neither."""
    key = _key_cache.get(proposal_id)
    if key:
        return key
    dk = _data_key()
    if dk and proposal_blob:
        try:
            key = _open(dk, proposal_blob)
            _key_cache[proposal_id] = key
            return key
        except Exception:
            return None
    return None
