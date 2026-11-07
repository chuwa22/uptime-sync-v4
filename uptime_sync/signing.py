"""HMAC signing of heartbeats and verification of the server's replies.

Request:  X-Signature = hex HMAC-SHA256(secret_key, <raw JSON body>)
Reply:    X-Response-Signature = hex HMAC-SHA256(secret_key,
              <request X-Signature> + "." + <raw reply body>)
Binding the request signature in stops a recorded reply being replayed.

A reply is the only thing that can make the agent restart or install code,
so verifying its signature only helps if unsigned replies are then refused
-- otherwise an attacker just deletes the header. remote.require_signed_response:
    true   always require a valid signature
    false  never (explicit opt-out)
    "auto" (default) require one once this server has signed a reply for
           this secret. The first valid signature writes a latch to
           data/response_signing.json; rotating the secret or moving to
           another server host starts a fresh latch instead of locking out.
The latch format is the same as Uptime Sync 3.6.22+, so `import` keeps it.
"""

import hashlib
import hmac
from urllib.parse import urlparse

from . import paths
from .util import active_server_url, atomic_write_json, read_json_for_update

_LATCH_CONTEXT = b'uptime-sync response-signing latch|'


def sign(secret_key, body):
    return hmac.new(secret_key.encode('utf-8'), body, hashlib.sha256).hexdigest()


def verify_reply(header, request_signature, body, secret_key):
    """'valid' | 'invalid' | 'unsigned'."""
    got = (header or '').strip().lower()
    if not got or not secret_key or not request_signature:
        return 'unsigned'
    expected = hmac.new(secret_key.encode('utf-8'),
                        request_signature.encode('utf-8') + b'.' + body,
                        hashlib.sha256).hexdigest()
    # bytes, not str: compare_digest raises TypeError on a non-ASCII str, and
    # the header is whatever the network sent.
    return 'valid' if hmac.compare_digest(got.encode('latin-1', 'replace'), expected.encode('ascii')) else 'invalid'


def mode(remote):
    value = remote.get('require_signed_response', 'auto')
    text = str(value).strip().lower()
    if value is True or text in ('true', '1', 'yes', 'on'):
        return True
    if value is False or text in ('false', '0', 'no', 'off'):
        return False
    return 'auto'


def fingerprint(remote):
    secret = (remote.get('secret_key') or '').strip()
    url = active_server_url(remote)
    if not secret or not url:
        return ''
    try:
        host = (urlparse(url).hostname or '').lower()
    except ValueError:
        return ''
    if not host:
        return ''
    return hmac.new(secret.encode('utf-8'), _LATCH_CONTEXT + host.encode('utf-8'),
                    hashlib.sha256).hexdigest()[:32]


def latched_since(remote):
    fp = fingerprint(remote)
    if not fp:
        return ''
    try:
        latch = read_json_for_update(paths.LATCH_FILE, {}) or {}
    except OSError:
        # Held by another program right now: an unreadable latch must not
        # read as "never latched" and let an unsigned reply through for
        # that beat (4.0.11). Treated as latched until it can be read.
        return '?'
    if isinstance(latch, dict) and hmac.compare_digest(str(latch.get('fingerprint', '')), fp):
        return str(latch.get('since') or '?')
    return ''


def save_latch(remote, since):
    fp = fingerprint(remote)
    if not fp:
        return False
    try:
        atomic_write_json(paths.LATCH_FILE, {'fingerprint': fp, 'since': since})
        return True
    except OSError:
        return False


def status(remote):
    """('required' | 'off' | 'enforced' | 'not-yet', since) for the UI."""
    m = mode(remote)
    if m is True:
        return 'required', ''
    if m is False:
        return 'off', ''
    since = latched_since(remote)
    return ('enforced', since) if since else ('not-yet', '')
