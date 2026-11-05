"""Heartbeat to uptime-monitor (api/heartbeat.php), protocol v1.

The JSON contract is additive-only and shared with Uptime Sync 3.x: never
rename or remove a field, read every reply field with a default, ignore
unknown fields. New behaviour is negotiated with a capability string, never
a version check. 'github-download' (new in 4.0) tells the server this agent
can fetch the release zip from GitHub; servers that do not know it keep
handing out their own download URL, which still works.
"""

import json
import logging
import os
import platform
import struct
import sys
import time

import requests
import urllib3

from . import __version__, paths, signing, updater
from .util import MIN_FREE_BYTES, USER_AGENT, free_bytes, iso_now, redact, server_tls_verify, url_host

# verify=False is used only where the admin chose it (a Local server, a
# monitor with ssl_verify off); urllib3 would otherwise write a warning
# to the child's stderr log on every request.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

log = logging.getLogger('heartbeat')

API_VERSION = 1
CAPABILITIES = (
    'sha256-verify',     # refuses an update without update_sha256
    'rollback-report',   # reports last_update_status=Failed after a rollback
    'force-install',     # honours force_install
    'scheduled-window',  # honours update_mode=scheduled + update_window
    'manual-install',    # honours update_mode=manual (Install button)
    'github-download',   # can download the release zip from GitHub
)
BACKOFF = (30, 60, 120, 300, 600)
TIMEOUT = 10


def arch():
    return 'x64' if struct.calcsize('P') == 8 else 'x86'


def disk_usage_mb():
    total = 0
    for d in (paths.LOG_DIR, paths.DATA_DIR):
        for base, _dirs, files in os.walk(d):
            for name in files:
                try:
                    total += os.path.getsize(os.path.join(base, name))
                except OSError:
                    pass
    return round(total / 1048576.0, 2)


def build_payload(settings, start_time, healthy=True):
    remote = settings.get('remote', {})
    status, when, version = updater.heartbeat_fields()
    return {
        'api_key': remote.get('api_key', '').strip(),
        'site_name': settings.get('site_name', ''),
        'service_version': __version__,
        'heartbeat_interval': max(30, int(remote.get('heartbeat_interval', 60) or 60)),
        'is_healthy': bool(healthy),
        'disk_usage_mb': disk_usage_mb(),
        'last_update_status': status,
        'last_update_time': when,
        'timestamp': int(time.time()),
        'agent_start_time': int(start_time),
        'api_version': API_VERSION,
        'arch': arch(),
        'python_version': '%d.%d.%d' % sys.version_info[:3],
        'platform': platform.platform(terse=True)[:120],
        'capabilities': list(CAPABILITIES),
        'last_update_version': version,
    }


class Heartbeat:
    def __init__(self, start_time):
        self.start_time = start_time
        self.failures = 0
        self.next_override = None     # seconds until the next beat, or None
        self._logged_verdict = None
        self._latch_warned = False
        self.last_ok = None           # epoch of the last 200 reply
        self.last_error = ''
        # One keep-alive connection to the server instead of a new TCP + TLS
        # handshake every beat.
        self.session = requests.Session()
        self.session.headers['User-Agent'] = USER_AGENT
        self._tls_note = None

    def interval(self, settings):
        if self.next_override:
            return self.next_override
        return max(30, int(settings.get('remote', {}).get('heartbeat_interval', 60) or 60))

    def send(self, settings, healthy=True):
        """POST one beat. Returns the reply dict if the agent may act on it
        (signature rules satisfied), {} if the reply must be ignored, or
        None on failure."""
        remote = settings.get('remote', {})
        url = (remote.get('url') or '').strip()
        secret = (remote.get('secret_key') or '').strip()
        if not url or not remote.get('api_key'):
            return None
        body = json.dumps(build_payload(settings, self.start_time, healthy)).encode('utf-8')
        headers = {'Content-Type': 'application/json'}
        sig = ''
        if secret:
            sig = signing.sign(secret, body)
            headers['X-Signature'] = sig
        verify = self._verify(remote)
        try:
            r = self.session.post(url, data=body, headers=headers, timeout=TIMEOUT,
                                  allow_redirects=False, verify=verify)
        except requests.RequestException as e:
            return self._fail('network error: %s' % redact(e))
        if 500 <= r.status_code < 600:
            return self._fail('server returned HTTP %d' % r.status_code)
        if r.status_code != 200:
            self.last_error = 'HTTP %d' % r.status_code
            log.warning('Heartbeat: server returned HTTP %d - check api_key / secret_key '
                        '(not backing off: the same request fails the same way)', r.status_code)
            return None
        try:
            data = r.json()
        except ValueError:
            return self._fail('reply is not JSON')
        if not isinstance(data, dict) or not data.get('success'):
            return self._fail('reply says success=false')
        if self.failures:
            log.info('Heartbeat recovered after %d failed attempt(s)', self.failures)
        self.failures = 0
        self.last_ok = time.time()
        self.last_error = ''
        nci = data.get('next_check_in')
        self.next_override = float(nci) if isinstance(nci, (int, float)) and 30 <= nci <= 3600 else None
        if data.get('deprecation_warning'):
            log.warning('[PROTOCOL] Server says: %s', data.get('deprecation_warning'))
        verdict = signing.verify_reply(r.headers.get('X-Response-Signature'), sig, r.content, secret)
        log.debug('Heartbeat OK (reply %s)', verdict)
        return data if self.may_act(verdict, remote) else {}

    def _verify(self, remote):
        verify = server_tls_verify(remote)
        local = str(remote.get('server_type') or 'public').lower() == 'local'
        note = (local, verify, url_host(remote.get('url')))
        if note != self._tls_note:
            self._tls_note = note
            if local and verify:
                log.warning('Server type is Local, but %s is not on the local network - its '
                            'certificate is checked as for a public server', note[2])
            elif local:
                log.info('Local server %s: a self-signed certificate is accepted', note[2])
        return verify

    def _fail(self, why):
        self.failures += 1
        delay = BACKOFF[min(self.failures, len(BACKOFF)) - 1]
        self.next_override = float(delay)
        self.last_error = why
        if self.failures == 1:
            log.info('Heartbeat failed (%s); retrying in %ds', why, delay)
        elif self.failures <= len(BACKOFF):
            log.warning('Heartbeat failed %dx in a row (%s); backing off to %ds',
                        self.failures, why, delay)
        return None

    def may_act(self, verdict, remote):
        """Signature rules: see signing.py."""
        m = signing.mode(remote)
        if verdict == 'valid' and m == 'auto' and not signing.latched_since(remote):
            if signing.save_latch(remote, iso_now()):
                log.info('[SECURITY] This server signs its heartbeat replies - unsigned replies '
                         'will be refused from now on (require_signed_response=auto)')
            elif not self._latch_warned:
                self._latch_warned = True
                log.warning('[SECURITY] Could not write data/response_signing.json - unsigned '
                            'replies stay accepted until it can be written')
        require = bool(signing.latched_since(remote)) if m == 'auto' else m
        if (verdict, require) != self._logged_verdict:
            self._logged_verdict = (verdict, require)
            if verdict == 'invalid':
                log.error('[SECURITY] Heartbeat reply signature does NOT match - ignoring its '
                          'settings/restart/update fields. Either secret_key differs between '
                          'this agent and the server, or the reply was altered in transit.')
            elif verdict == 'valid':
                log.info('[SECURITY] Heartbeat replies are signed by the server and verified')
            elif require and m == 'auto':
                log.warning('[SECURITY] Heartbeat reply is NOT signed, but this server has signed '
                            'them before - ignoring server-pushed settings, restarts and updates. '
                            'Set the secret again on the agent card in uptime-monitor, or set '
                            'remote.require_signed_response to false to accept unsigned replies.')
            elif require:
                log.warning('[SECURITY] Heartbeat reply is not signed and require_signed_response '
                            'is on - ignoring server-pushed settings, restarts and updates')
        if verdict == 'invalid':
            return False
        return verdict == 'valid' or not require


def free_disk_ok():
    free = free_bytes(paths.ROOT)
    return free is None or free > MIN_FREE_BYTES
