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
import hmac
import json
import os
import secrets
import threading
import time
from collections import OrderedDict

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

# Decrypted Telinea keys live only in process memory, keyed by proposal
# id. Never written to disk plaintext. Bounded LRU: plaintext keys are
# high-value, so the cache can't grow without limit.
_KEY_CACHE_MAX = 1024
_key_cache = OrderedDict()

# Serializes the accounts.json read-modify-write in register() -- two
# concurrent registrations must not clobber each other.
_register_lock = threading.Lock()

# A well-formed blob under a throwaway key, built lazily. unlock()
# decrypts it when the account doesn't exist so the missing-account
# path costs the same HKDF+GCM work as the wrong-key path -- account
# existence isn't oracle-able by timing.
_dummy_blob = None


def _get_dummy_blob():
    global _dummy_blob
    if _dummy_blob is None:
        _dummy_blob = _seal(os.urandom(32), b"timing-equalization")
    return _dummy_blob


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
    """Store telinea_key encrypted under a key derived from quorum_key.
    Returns the account id."""
    with _register_lock:
        accounts = _load_accounts()
        account_id = account_id_for(quorum_key)
        salt = os.urandom(32)
        accounts[account_id] = {
            "salt": base64.b64encode(salt).decode(),
            "blob": _seal(_kek(quorum_key, salt), telinea_key),
        }
        _save_accounts(accounts)
    return account_id


def count():
    """Registered account count -- used to cap growth."""
    return len(_load_accounts())


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
        # Same HKDF+GCM work as the wrong-key path: account existence
        # stays indistinguishable by timing.
        try:
            _open(_kek(quorum_key, b"\x00" * 32), _get_dummy_blob())
        except Exception:
            pass
        return None
    try:
        salt = base64.b64decode(rec["salt"])
        # Field was "blob" in early accounts.json files; accept both.
        blob = rec.get("telinea_key_enc") or rec.get("blob")
        return account_id, _open(_kek(quorum_key, salt), blob)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Proposal-scoped access: how spans authenticate after the orchestrator's
# Quorum key is gone from the request path.
# ---------------------------------------------------------------------------

def cache_key(proposal_id, telinea_key):
    _key_cache[proposal_id] = telinea_key
    _key_cache.move_to_end(proposal_id)
    while len(_key_cache) > _KEY_CACHE_MAX:
        _key_cache.popitem(last=False)


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
        _key_cache.move_to_end(proposal_id)
        return key
    dk = _data_key()
    if dk and proposal_blob:
        try:
            key = _open(dk, proposal_blob)
            cache_key(proposal_id, key)
            return key
        except Exception:
            return None
    return None
