"""The five check types. Each returns (ok, response_ms, dns_ms).

Stdlib + requests only. DNS server probes speak the DNS wire format
directly (no dnspython), and ping shells out to the OS `ping` because raw
ICMP sockets need root/admin on every platform.
"""

import datetime
import logging
import os
import re
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
from urllib.parse import urlparse

import certifi
import requests

from . import __version__

DNS_METHODS = ('auto', 'query', 'ping')
DNS_DEFAULT_QUERY_NAME = 'google.com'
_DNS_LABEL_RE = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?$')
_PING_TIME_RE = re.compile(r'[=<]\s*(\d+(?:\.\d+)?)\s*ms', re.I)

log = logging.getLogger('checks')


def is_valid_dns_query_name(name):
    """True for an ASCII host name usable as a DNS query name ('.' = root)."""
    if not isinstance(name, str):
        return False
    name = name.strip()
    if name == '.':
        return True
    name = name.rstrip('.')
    if not name or len(name) > 253:
        return False
    return all(_DNS_LABEL_RE.match(label) for label in name.split('.'))


def is_ip_literal(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return True
        except (OSError, ValueError):
            pass
    return False


def ping_command(host, timeout):
    """The OS ping invocation for one echo request."""
    timeout = max(1, int(timeout))
    if sys.platform.startswith('win'):
        return ['ping', '-n', '1', '-w', str(timeout * 1000), host]
    if sys.platform == 'darwin':
        if ':' in host:
            return ['ping6', '-c', '1', host]
        return ['ping', '-c', '1', '-t', str(timeout), host]
    return ['ping', '-c', '1', '-W', str(timeout), host]


def parse_ping(returncode, output, elapsed_ms):
    """Response time in ms from ping output, or None when there was no reply.

    Windows exits 0 even for "Destination host unreachable" sent back by a
    router, so a real reply there is recognised by its TTL= field (present
    in every language Windows ships) or, for IPv6 replies, which have no TTL,
    by the time field. That field is localised around
    '=' / '<' + digits + 'ms'; when it cannot be parsed the wall-clock time
    of the ping process stands in.
    """
    if returncode != 0:
        return None
    m = _PING_TIME_RE.search(output)
    if sys.platform.startswith('win') and 'TTL=' not in output.upper() and not m:
        # IPv6 replies carry no TTL ("Reply from ::1: time<1ms"), but they do
        # carry the time; "unreachable" / "TTL expired" lines carry neither.
        return None
    if m:
        return round(float(m.group(1)), 1)
    return round(elapsed_ms, 1)


class Checker:
    _DNS_FAILURE_THRESHOLD = 3
    _DNS_CIRCUIT_OPEN_SECONDS = 60
    _DNS_AUTO_QUERY_BUDGET_SECONDS = 4.0
    _HTTP_MAX_REDIRECTS = 5

    def __init__(self):
        self.session = requests.Session()
        self.session.headers['User-Agent'] = 'UptimeSync/%s' % __version__
        self.session.max_redirects = self._HTTP_MAX_REDIRECTS
        self._lock = threading.Lock()
        self._dns_failures = {}        # host -> (count, opened_at)
        self._dns_ping_fallback = set()
        self._ssl_warned = {}          # host -> day last warned

    # -- dispatch ----------------------------------------------------------

    def check(self, m):
        kind = m['type']
        target = m['target']
        timeout = m['timeout']
        if target.startswith('-'):
            return False, 0, 0
        if kind == 'DNS':
            ok, ms = self.check_dns(target, timeout, m.get('dns_method'), m.get('dns_query_name'))
            return ok, ms, 0
        if kind == 'PING':
            ms = self.ping(target, timeout)
            return ms is not None, ms or 0, 0
        if kind == 'TCP PORT':
            ok, ms = self.check_tcp(target, m['port'] or 80, timeout)
            return ok, ms, 0
        if kind in ('HTTP', 'HTTPS'):
            scheme = kind.lower()
            url = m['monitor_url'] or '%s://%s%s' % (
                scheme, target, (':%d' % m['port']) if m['port'] else '')
            if kind == 'HTTPS' and not url.lower().startswith('https://'):
                url = 'https://' + url.split('://', 1)[-1]
            ok, ms = self.check_http(url, timeout, m.get('headers'), m.get('ssl_verify', True))
            host = urlparse(url).hostname or target
            _, dns_ms = self.check_dns(host, timeout) if not is_ip_literal(host) else (True, 0)
            if kind == 'HTTPS' and ok and m.get('ssl_verify', True):
                self._warn_ssl_expiry(host, urlparse(url).port or 443, timeout)
            return ok, ms, dns_ms
        log.warning('Unknown monitor type %r for %s', kind, m.get('name'))
        return False, 0, 0

    # -- ping --------------------------------------------------------------

    def ping(self, host, timeout=10):
        cmd = ping_command(host, timeout)
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        start = time.monotonic()
        try:
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  stdin=subprocess.DEVNULL, timeout=timeout + 2,
                                  creationflags=flags)
        except subprocess.TimeoutExpired:
            log.debug('ping %s timed out', host)
            return None
        except OSError as e:
            log.warning('ping could not run (%s): %s', cmd[0], e)
            return None
        output = proc.stdout.decode('latin-1', errors='replace')
        return parse_ping(proc.returncode, output, (time.monotonic() - start) * 1000)

    # -- DNS ---------------------------------------------------------------

    def check_dns(self, target, timeout=10, method='auto', query_name=''):
        """IP literal = probe that DNS server. Host name = resolve it."""
        if not target:
            return False, 0
        if is_ip_literal(target):
            try:
                return self._check_dns_server(target, timeout, method, query_name)
            except Exception as e:
                log.debug('DNS server check %s failed: %s', target, e)
                return False, 0
        if self._circuit_open(target):
            return False, 0
        start = time.monotonic()
        try:
            socket.getaddrinfo(target, None)
        except Exception as e:
            log.debug('resolve %s failed: %s', target, e)
            self._mark_failure(target)
            return False, 0
        self._mark_success(target)
        return True, int((time.monotonic() - start) * 1000)

    def _check_dns_server(self, server, timeout, method, query_name):
        """'query' = DNS over UDP/53 only; 'ping' = ICMP only; 'auto' = query,
        then ping if the server does not answer. Some public resolvers
        (Level3 4.2.2.x) drop ICMP but answer DNS, so ping alone calls them
        down; the fallback keeps a gateway used as a "DNS" target working."""
        method = str(method or 'auto').lower()
        if method not in DNS_METHODS:
            method = 'auto'
        start = time.monotonic()
        if method != 'ping':
            budget = float(timeout) if method == 'query' else min(
                float(timeout) / 2.0, self._DNS_AUTO_QUERY_BUDGET_SECONDS)
            rtt = self.query_dns_server(server, query_name or DNS_DEFAULT_QUERY_NAME, budget)
            if rtt is not None:
                if method == 'auto':
                    self._note_fallback(server, False)
                return True, rtt
            if method == 'query':
                return False, 0
        remaining = max(1, int(round(float(timeout) - (time.monotonic() - start))))
        ms = self.ping(server, remaining)
        if ms is None:
            return False, 0
        if method == 'auto':
            self._note_fallback(server, True)
        return True, ms

    def _note_fallback(self, server, using_ping):
        with self._lock:
            if (server in self._dns_ping_fallback) == using_ping:
                return
            (self._dns_ping_fallback.add if using_ping else self._dns_ping_fallback.discard)(server)
        if using_ping:
            log.info('[DNS] %s did not answer the DNS query but answers ping; '
                     'reporting up on ping until DNS answers again', server)
        else:
            log.info('[DNS] %s answers DNS queries again', server)

    @staticmethod
    def build_dns_query(txid, query_name):
        """Wire-format query, RD set, class IN: A record, or NS for root '.'."""
        name = (query_name or DNS_DEFAULT_QUERY_NAME).strip()
        if not is_valid_dns_query_name(name):
            name = DNS_DEFAULT_QUERY_NAME
        name = name.rstrip('.')
        qname = b''.join(struct.pack('B', len(label)) + label.encode('ascii')
                         for label in name.split('.') if label) + b'\x00'
        qtype = 1 if name else 2
        return struct.pack('>HHHHHH', txid, 0x0100, 1, 0, 0, 0) + qname + struct.pack('>HH', qtype, 1)

    def query_dns_server(self, server, query_name=DNS_DEFAULT_QUERY_NAME, timeout=4.0, attempts=2):
        """RTT in ms of a DNS query to server:53/udp, or None without an answer.

        Any well-formed response with our transaction ID counts, whatever its
        RCODE -- REFUSED still proves the server is reachable. The timeout is
        split over `attempts` sends so one lost datagram is not an outage."""
        family = socket.AF_INET6 if ':' in server else socket.AF_INET
        per_try = max(0.5, float(timeout) / max(1, attempts))
        sent = {}
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.connect((server, 53))
            for _ in range(max(1, attempts)):
                txid = struct.unpack('>H', os.urandom(2))[0]
                sent[txid] = time.monotonic()
                sock.send(self.build_dns_query(txid, query_name))
                deadline = sent[txid] + per_try
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    sock.settimeout(remaining)
                    try:
                        data = sock.recv(4096)
                    except socket.timeout:
                        break
                    if len(data) < 12:
                        continue
                    rid, flags = struct.unpack('>HH', data[:4])
                    if rid in sent and flags & 0x8000:
                        return round((time.monotonic() - sent[rid]) * 1000, 1)
            return None
        except OSError as e:
            log.debug('DNS query to %s failed: %s', server, e)
            return None
        finally:
            sock.close()

    def _circuit_open(self, host):
        """After 3 straight resolve failures, fail fast for 60 s so N
        monitors sharing a dead domain do not each wait out the resolver."""
        with self._lock:
            count, opened = self._dns_failures.get(host, (0, 0))
            if not opened:
                return False
            if time.monotonic() - opened > self._DNS_CIRCUIT_OPEN_SECONDS:
                self._dns_failures[host] = (0, 0)
                return False
            return True

    def _mark_failure(self, host):
        with self._lock:
            count, opened = self._dns_failures.get(host, (0, 0))
            count += 1
            if count >= self._DNS_FAILURE_THRESHOLD and not opened:
                opened = time.monotonic()
                log.warning('[DNS] %s failed to resolve %d times; skipping it for %ds',
                            host, count, self._DNS_CIRCUIT_OPEN_SECONDS)
            self._dns_failures[host] = (count, opened)

    def _mark_success(self, host):
        with self._lock:
            count, opened = self._dns_failures.get(host, (0, 0))
            if opened:
                log.info('[DNS] %s resolves again', host)
            self._dns_failures[host] = (0, 0)

    # -- TCP / HTTP --------------------------------------------------------

    def check_tcp(self, host, port, timeout=10):
        start = time.monotonic()
        try:
            with socket.create_connection((host, int(port)), timeout=timeout):
                return True, int((time.monotonic() - start) * 1000)
        except (OSError, ValueError) as e:
            log.debug('TCP %s:%s failed: %s', host, port, e)
            return False, 0

    def check_http(self, url, timeout=10, headers=None, verify=True):
        """Up = any 2xx/3xx after at most 5 redirects."""
        start = time.monotonic()
        try:
            r = self.session.get(url, timeout=timeout, headers=headers or {}, verify=verify,
                                 allow_redirects=True, stream=True)
            r.close()
        except Exception as e:   # noqa: BLE001 -- a bad header value raises UnicodeEncodeError
            # Never the URL or the raw error: an expanded ${NAME} from data/.env
            # may sit in its query string.
            u = urlparse(url)
            log.debug('HTTP %s://%s failed: %s', u.scheme, u.hostname, type(e).__name__)
            return False, 0
        ms = int((time.monotonic() - start) * 1000)
        return 200 <= r.status_code < 400, ms

    def _warn_ssl_expiry(self, host, port, timeout):
        """Warn (once a day per host) when a certificate expires within 30 days."""
        today = datetime.date.today()
        if self._ssl_warned.get(host) == today:
            return
        self._ssl_warned[host] = today
        try:
            # certifi's bundle, the one requests uses: Windows 7's own root
            # store lacks most of today's roots, so the default context would
            # fail on a site the HTTP check itself just reached fine.
            ctx = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((host, int(port)), timeout=timeout) as raw:
                with ctx.wrap_socket(raw, server_hostname=host) as s:
                    not_after = s.getpeercert().get('notAfter')
            days = int((ssl.cert_time_to_seconds(not_after) - time.time()) // 86400)
        except Exception as e:
            log.debug('certificate check %s failed: %s', host, e)
            return
        if days < 0:
            log.warning('Certificate for %s EXPIRED %d day(s) ago', host, -days)
        elif days < 30:
            log.warning('Certificate for %s expires in %d day(s)', host, days)
