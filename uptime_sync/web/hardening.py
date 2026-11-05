"""Fixes for the web stack that Windows 7 (Python 3.8) cannot get by
upgrading: the releases with the fix no longer install there, and pip runs
from the OLD agent's code during an update, so no pip flag can be added to
force them. Each is applied on every Python, so the tests see one behaviour.
"""

import logging

log = logging.getLogger('web')

# werkzeug 3.1.4-3.1.9 (CVE-2025-66221, CVE-2026-21860, CVE-2026-27199,
# CVE-2026-102598): on Windows a path segment naming a DOS device (NUL,
# CON, COM1.txt, "aux .x", "nul:") opens the device, and reading it hangs a
# waitress thread. 3.0.6, the last werkzeug for 3.8, has none of these
# checks. Same rule as werkzeug 3.1.9's safe_join; COM/LPT with superscript
# digits count too.
_DEVICES = frozenset(['AUX', 'CON', 'CONIN$', 'CONOUT$', 'NUL', 'PRN'] +
                     ['%s%s' % (p, d) for p in ('COM', 'LPT') for d in '123456789\u00b9\u00b2\u00b3'])


def names_a_device(path):
    """True when a segment of the URL path is a Windows device name."""
    for seg in path.split('/'):
        if seg.partition(':')[0].partition('.')[0].strip().upper() in _DEVICES:
            return True
    return False


# waitress 3.0.1 (CVE-2024-49769): a client that closes its connection
# before getpeername() runs leaves a channel marked not connected; its
# handle_write then returns at once forever, a busy loop that holds the
# socket, so a few such connections take the web UI down. 3.0.1 marks the
# channel connected (the socket came from accept()); writing then fails and
# closes it. This is that change, for 3.0.0, the last waitress for 3.8.
# (CVE-2024-49768 needs channel_request_lookahead > 0; SERVE_OPTIONS pins 0.)
SERVE_OPTIONS = {'threads': 6, 'ident': 'UptimeSync', 'channel_request_lookahead': 0}


def _waitress_version():
    try:
        from importlib.metadata import version
        return version('waitress')
    except Exception:   # noqa: BLE001 -- no metadata: assume it needs nothing
        return ''


def patch_waitress():
    """Backport the 3.0.1 channel fix onto waitress 3.0.0. True if applied."""
    if _waitress_version() != '3.0.0':
        return False
    from waitress import channel
    original = channel.HTTPChannel.__init__
    if getattr(original, 'uptime_sync_fix', False):
        return True

    def __init__(self, server, sock, addr, adj, map=None):
        original(self, server, sock, addr, adj, map)
        self.connected = True
    __init__.uptime_sync_fix = True
    channel.HTTPChannel.__init__ = __init__
    log.debug('waitress 3.0.0: CVE-2024-49769 fix applied')
    return True


