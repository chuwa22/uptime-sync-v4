"""HTTPS for the web UI (4.4.0), `web.https` in the settings.

waitress speaks plain HTTP only, so TLS is added per connection here: the
server's channel_class is swapped for TLSChannel, which wraps the accepted
socket with ssl (non-blocking) and feeds the decrypted bytes to waitress's
own parser. Everything else (threads, limits, timeouts, the CVE fixes in
hardening.py) is unchanged, and REMOTE_ADDR is still the browser's address,
so the sign-in throttle keeps working per client.

A connection that starts with anything but a TLS handshake (an old
http:// bookmark) gets a 302 to the same path on https://, then is closed.

Certificate: data/tls/cert.pem + key.pem when the admin put their own there
(PEM, key without a passphrase); otherwise the agent's own self-signed
data/tls/self-signed.pem + .key, made on first use by certgen.py and made
again 30 days before it ends. A broken own certificate falls back to the
self-signed one with an ERROR, so the web UI never drops to plain http.

TLS 1.2 and 1.3 only, ECDHE key exchange. Windows 7: IE11 has TLS 1.2 on;
IE8-IE10 need Internet Options > Advanced > Use TLS 1.2 (Windows 7's
schannel has it, IE just does not tick it). TLS 1.0 / 1.1 stay off.
"""

import datetime
import logging
import os
import re
import socket
import ssl
import time

from waitress.channel import HTTPChannel

from .. import paths
from ..util import atomic_write_text
from . import certgen

log = logging.getLogger('web')

TLS_DIR = os.path.join(paths.DATA_DIR, 'tls')
OWN_CERT = os.path.join(TLS_DIR, 'cert.pem')
OWN_KEY = os.path.join(TLS_DIR, 'key.pem')
SELF_CERT = os.path.join(TLS_DIR, 'self-signed.pem')
SELF_KEY = os.path.join(TLS_DIR, 'self-signed.key')
RENEW_DAYS = 30

# ECDHE only (forward secrecy). ECDHE+AES keeps the CBC-SHA256/384 suites
# that Windows 7's schannel offers for an RSA certificate with TLS 1.2.
CIPHERS = 'ECDHE+AESGCM:ECDHE+CHACHA20:ECDHE+AES:!aNULL:!eNULL:!MD5:!3DES:!SHA1'

# What this process serves, for the Settings page: None (plain http) or
# {'source': 'own'|'self-signed', 'cert': path, 'fingerprint', 'not_after',
#  'error': why the admin's own certificate was not used, or ''}.
ACTIVE = None


def _no_password():
    # An encrypted key would otherwise make OpenSSL prompt on a console
    # that pythonw does not have. b'' fails cleanly instead.
    return b''


def _context(cert, key):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.set_ciphers(CIPHERS)
    ctx.options |= (ssl.OP_NO_COMPRESSION | ssl.OP_CIPHER_SERVER_PREFERENCE |
                    getattr(ssl, 'OP_NO_RENEGOTIATION', 0))
    ctx.load_cert_chain(cert, key, password=_no_password)
    return ctx


def _cert_der(path):
    with open(path, 'r', encoding='ascii') as f:
        text = f.read()
    m = re.search(r'-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----', text, re.S)
    if not m:
        raise ValueError('no certificate in %s' % os.path.basename(path))
    return ssl.PEM_cert_to_DER_cert(m.group(0))


def describe(path):
    """{'fingerprint', 'not_after'} of the first certificate in a PEM file."""
    der = _cert_der(path)
    return {'fingerprint': certgen.fingerprint(der), 'not_after': certgen.validity(der)[1]}


def _utcnow():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def ensure_self_signed(host='', now=None):
    """Make data/tls/self-signed.pem + .key when missing, unreadable or
    ending within RENEW_DAYS. True when a new one was made."""
    now = now or _utcnow()
    try:
        info = describe(SELF_CERT)
        if os.path.isfile(SELF_KEY) and info['not_after'] - now > datetime.timedelta(days=RENEW_DAYS):
            return False
        why = 'ends %s UTC' % info['not_after'].strftime('%Y-%m-%d')
    except FileNotFoundError:
        why = 'none yet'
    except (OSError, ValueError) as e:
        why = 'unreadable: %s' % e
    log.info('Making a self-signed certificate for the web UI (%s); this takes a few seconds', why)
    os.makedirs(TLS_DIR, mode=0o700, exist_ok=True)
    cn, dns, ips = certgen.local_names(host)
    cert_pem, key_pem, der = certgen.make(cn, dns, ips, now=now)
    # Key first: a cert without its key is "missing" next time, never a pair
    # that does not match.
    atomic_write_text(SELF_KEY, key_pem, private=True)
    atomic_write_text(SELF_CERT, cert_pem, private=True)
    log.info('Self-signed certificate made for %s, SHA-256 %s', ', '.join(dns + ips),
             certgen.fingerprint(der))
    return True


def server_context(host=''):
    """(SSLContext, ACTIVE dict) for the web UI. The admin's own
    certificate when there is one that loads, else the self-signed one."""
    error = ''
    if os.path.exists(OWN_CERT) or os.path.exists(OWN_KEY):
        try:
            ctx = _context(OWN_CERT, OWN_KEY)
            info = dict(describe(OWN_CERT), source='own', cert=OWN_CERT, error='')
            return ctx, info
        except (OSError, ValueError, ssl.SSLError) as e:
            error = '%s: %s' % (type(e).__name__, e)
            log.error('data/tls/cert.pem + key.pem cannot be used (%s) - serving the '
                      'self-signed certificate instead', error)
    ensure_self_signed(host)
    ctx = _context(SELF_CERT, SELF_KEY)
    info = dict(describe(SELF_CERT), source='self-signed', cert=SELF_CERT, error=error)
    return ctx, info

# -- the waitress side -----------------------------------------------------------

_HOST_RE = re.compile(r'^([A-Za-z0-9.-]{1,253}|\[[0-9A-Fa-f:.]{2,45}\])(:[0-9]{1,5})?$')
_PATH_RE = re.compile(r'^/[\x21-\x7e]{0,2047}$')
_PLAIN_HEAD_MAX = 8192


def redirect_for(head, local=None):
    """The bytes to answer a plain-http request on the https port: a 302
    to https://<Host><path>, or a 400 when the request cannot be read."""
    lines = head.split(b'\r\n')
    parts = lines[0].split(b' ')
    host = None
    for line in lines[1:]:
        name, _, value = line.partition(b':')
        if name.strip().lower() == b'host':
            host = value.strip().decode('latin-1')
            break
    if host is None and local:
        addr, port = local[0], local[1]
        host = ('[%s]' % addr if ':' in addr else addr) + ':%d' % port
    path = parts[1].decode('latin-1') if len(parts) == 3 else ''
    if not host or not _HOST_RE.match(host) or not parts[-1].startswith(b'HTTP/'):
        body = b'This port speaks HTTPS only: open it with https://\n'
        return (b'HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain\r\n'
                b'Content-Length: %d\r\nConnection: close\r\n\r\n' % len(body)) + body
    if not _PATH_RE.match(path):
        path = '/'
    # 302, not 301: browsers keep a 301 for ever, and https may be turned
    # off again later.
    location = ('https://%s%s' % (host, path)).encode('ascii')
    body = b'<a href="' + location.replace(b'"', b'%22') + b'">Moved to https</a>\n'
    return (b'HTTP/1.1 302 Found\r\nLocation: ' + location + b'\r\n'
            b'Content-Type: text/html\r\nContent-Length: %d\r\n'
            b'Cache-Control: no-store\r\nConnection: close\r\n\r\n' % len(body)) + body


class TLSChannel(HTTPChannel):
    """An HTTPChannel over ssl. States: 'sniff' (nothing read yet),
    'plain' (not TLS: answer with redirect_for, close), 'handshake',
    'open'. ssl's non-blocking errors are "try again later": WantRead
    waits for readable (waitress does that anyway), WantWrite makes
    writable() true until the same call is tried again."""

    tls_context = None   # set on the subclass that install() makes

    def __init__(self, server, sock, addr, adj, map=None):
        self._tls_state = 'sniff'
        self._tls_want_write = False
        self._plain = b''
        HTTPChannel.__init__(self, server, sock, addr, adj, map)

    # -- reading

    def readable(self):
        if self._tls_state != 'open':
            return not self.will_close
        return HTTPChannel.readable(self)

    def handle_read(self):
        state = self._tls_state
        if state == 'sniff':
            self._sniff()
        elif state == 'plain':
            self._read_plain()
        elif state == 'handshake':
            if self._handshake():
                self._read_tls()
        else:
            self._read_tls()

    def _close_quietly(self, what, err):
        log.debug('HTTPS %s with %s: %s', what, self.addr[0] if self.addr else '?', err)
        self.handle_close()

    def _sniff(self):
        try:
            first = self.socket.recv(1, socket.MSG_PEEK)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as e:
            return self._close_quietly('connection', e)
        if not first:
            return self.handle_close()
        if first != b'\x16':                  # not a TLS handshake record
            self._tls_state = 'plain'
            return self._read_plain()
        try:
            self.socket = self.tls_context.wrap_socket(
                self.socket, server_side=True, do_handshake_on_connect=False)
        except (OSError, ValueError) as e:
            return self._close_quietly('connection', e)
        self._tls_state = 'handshake'
        if self._handshake():
            self._read_tls()

    def _read_plain(self):
        try:
            chunk = self.socket.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError as e:
            return self._close_quietly('plain request', e)
        if not chunk:
            return self.handle_close()
        self._plain += chunk
        if b'\r\n\r\n' not in self._plain and len(self._plain) < _PLAIN_HEAD_MAX:
            return
        head = self._plain.split(b'\r\n\r\n', 1)[0]
        try:
            local = self.socket.getsockname()
        except OSError:
            local = None
        try:
            self.socket.send(redirect_for(head, local))
        except OSError as e:
            log.debug('HTTPS redirect to %s not sent: %s', self.addr[0], e)
        self.handle_close()

    def _handshake(self):
        try:
            self.socket.do_handshake()
        except ssl.SSLWantReadError:
            return False
        except ssl.SSLWantWriteError:
            self._tls_want_write = True
            return False
        except (ssl.SSLError, OSError, ValueError) as e:
            # A browser that does not trust the self-signed certificate
            # yet ends every attempt here: DEBUG, not a warning.
            self._close_quietly('handshake', e)
            return False
        self._tls_state = 'open'
        return True

    def _read_tls(self):
        data = []
        closed = False
        try:
            while True:
                chunk = self.socket.recv(self.adj.recv_bytes)
                if not chunk:
                    closed = True
                    break
                data.append(chunk)
                # Bytes ssl already decrypted never show up in select():
                # take them now or the request waits for the next packet.
                if not self.socket.pending():
                    break
        except ssl.SSLWantReadError:
            pass
        except ssl.SSLWantWriteError:
            self._tls_want_write = True
        except (ssl.SSLError, OSError) as e:
            return self._close_quietly('read', e)
        if data:
            self.last_activity = time.time()
            self.received(b''.join(data))
        if closed:
            self.handle_close()

    # -- writing

    def writable(self):
        return self._tls_want_write or HTTPChannel.writable(self)

    def handle_write(self):
        if self._tls_want_write:
            self._tls_want_write = False
            self.handle_read()          # the call that needed to write, again
        if not self.connected:
            return
        if self._tls_state != 'open':   # waitress's idle timeout before a request
            if self.will_close:
                self.handle_close()
            return
        HTTPChannel.handle_write(self)

    def send(self, data, do_close=True):
        try:
            return HTTPChannel.send(self, data, do_close=do_close)
        except (ssl.SSLWantWriteError, ssl.SSLWantReadError):
            return 0                    # the same bytes are offered again
        except ssl.SSLError as e:
            log.debug('HTTPS write to %s: %s', self.addr[0], e)
            if do_close:
                self.handle_close()
            return 0


def install(server_map, context):
    """Make every waitress server in server_map hand its connections to a
    TLSChannel that uses context."""
    from waitress.server import BaseWSGIServer
    channel = type('TLSChannel', (TLSChannel,), {'tls_context': context})
    count = 0
    for d in list(server_map.values()):
        if isinstance(d, BaseWSGIServer):
            d.channel_class = channel
            count += 1
    return count


def create_server(app, context, **kw):
    """waitress.create_server with TLS on every listening socket."""
    from waitress.server import create_server as waitress_create
    server_map = {}
    server = waitress_create(app, map=server_map, url_scheme='https', **kw)
    if not install(server_map, context):
        raise RuntimeError('no waitress server to put TLS on')
    return server
