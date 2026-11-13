"""A self-signed TLS certificate for the web UI, made with the standard
library only (4.4.0). requirements.txt has no crypto package, and Windows 7
boxes have no openssl.exe, so this is RSA (Miller-Rabin primes, pow()) and
a small DER writer for one X.509 v3 certificate:

    RSA 2048, e = 65537, signed sha256WithRSAEncryption (PKCS#1 v1.5)
    subject = issuer = CN=<computer name>, O=Uptime Sync (self-signed)
    825 days (Apple's limit for a TLS server certificate), from a day ago
    basicConstraints CA:FALSE, keyUsage digitalSignature + keyEncipherment,
    extendedKeyUsage serverAuth, subjectAltName: the computer name,
    localhost, 127.0.0.1, ::1 and this computer's addresses

Windows 7 (IE11, schannel) accepts all of this: RSA 2048 and SHA-256 are
older than it. ssl.SSLContext.load_cert_chain() is the check that the
files are right; the tests do a real handshake with them.
"""

import base64
import datetime
import hashlib
import ipaddress
import re
import secrets
import socket

KEY_BITS = 2048
VALID_DAYS = 825
_E = 65537

# -- RSA -----------------------------------------------------------------------

_SMALL_PRIMES = [p for p in range(3, 2000) if all(p % d for d in range(2, int(p ** 0.5) + 1))]


def _probable_prime(n, rounds=8):
    """Miller-Rabin with random bases. 8 rounds is more than FIPS 186-4
    asks for random 1024-bit candidates (error below 2**-100)."""
    for p in _SMALL_PRIMES:
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        # Top two bits set: p * q then has exactly 2 * bits bits.
        n = secrets.randbits(bits) | (3 << (bits - 2)) | 1
        if (n - 1) % _E and _probable_prime(n):
            return n


def _gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def new_key(bits=KEY_BITS):
    """{'n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi'} for a new RSA key."""
    half = bits // 2
    while True:
        p, q = _prime(half), _prime(bits - half)
        if p == q:
            continue
        if p < q:
            p, q = q, p
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = (p - 1) * (q - 1) // _gcd(p - 1, q - 1)
        d = pow(_E, -1, lam)
        return {'n': n, 'e': _E, 'd': d, 'p': p, 'q': q,
                'dp': d % (p - 1), 'dq': d % (q - 1), 'qi': pow(q, -1, p)}


def _int_bytes(value, size):
    return value.to_bytes(size, 'big')


# SEQUENCE { SEQUENCE { sha256 OID, NULL }, OCTET STRING (32) }, RFC 8017 9.2
_SHA256_INFO = bytes.fromhex('3031300d060960864801650304020105000420')


def _sign(key, message):
    """RSASSA-PKCS1-v1_5 with SHA-256 (CRT)."""
    k = (key['n'].bit_length() + 7) // 8
    t = _SHA256_INFO + hashlib.sha256(message).digest()
    em = b'\x00\x01' + b'\xff' * (k - len(t) - 3) + b'\x00' + t
    m = int.from_bytes(em, 'big')
    m1 = pow(m, key['dp'], key['p'])
    m2 = pow(m, key['dq'], key['q'])
    h = (key['qi'] * (m1 - m2)) % key['p']
    s = m2 + h * key['q']
    if pow(s, key['e'], key['n']) != m:     # a fault in the maths: never hand it out
        raise ValueError('RSA signature check failed')
    return _int_bytes(s, k)

# -- DER -----------------------------------------------------------------------


def _tlv(tag, content):
    n = len(content)
    if n < 0x80:
        size = bytes([n])
    else:
        raw = n.to_bytes((n.bit_length() + 7) // 8, 'big')
        size = bytes([0x80 | len(raw)]) + raw
    return bytes([tag]) + size + content


def _seq(*items):
    return _tlv(0x30, b''.join(items))


def _int(value):
    raw = value.to_bytes(value.bit_length() // 8 + 1, 'big')   # leading 0 keeps it positive
    while len(raw) > 1 and raw[0] == 0 and raw[1] < 0x80:
        raw = raw[1:]
    return _tlv(0x02, raw)


def _oid(dotted):
    parts = [int(x) for x in dotted.split('.')]
    out = bytearray([40 * parts[0] + parts[1]])
    for value in parts[2:]:
        chunk = [value & 0x7f]
        value >>= 7
        while value:
            chunk.append(0x80 | (value & 0x7f))
            value >>= 7
        out.extend(reversed(chunk))
    return _tlv(0x06, bytes(out))


_NULL = b'\x05\x00'
_RSA_ENCRYPTION = _seq(_oid('1.2.840.113549.1.1.1'), _NULL)
_SHA256_RSA = _seq(_oid('1.2.840.113549.1.1.11'), _NULL)


def _time(when):
    # RFC 5280 4.1.2.5: UTCTime up to 2049, GeneralizedTime from 2050.
    if when.year < 2050:
        return _tlv(0x17, when.strftime('%y%m%d%H%M%SZ').encode('ascii'))
    return _tlv(0x18, when.strftime('%Y%m%d%H%M%SZ').encode('ascii'))


def _name(common_name):
    def rdn(oid, text):
        return _tlv(0x31, _seq(_oid(oid), _tlv(0x0c, text.encode('utf-8'))))
    return _seq(rdn('2.5.4.10', 'Uptime Sync (self-signed)'), rdn('2.5.4.3', common_name))


def _extension(oid, value, critical=False):
    return _seq(_oid(oid), b'\x01\x01\xff' if critical else b'', _tlv(0x04, value))


def _alt_names(dns_names, ips):
    names = [_tlv(0x82, n.encode('ascii')) for n in dns_names]
    names += [_tlv(0x87, ipaddress.ip_address(ip).packed) for ip in ips]
    return _seq(*names)


def public_key_der(key):
    rsa = _seq(_int(key['n']), _int(key['e']))
    return _seq(_RSA_ENCRYPTION, _tlv(0x03, b'\x00' + rsa))


def certificate_der(key, common_name, dns_names, ips, now=None, days=VALID_DAYS):
    now = (now or datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).replace(microsecond=0)
    not_before = now - datetime.timedelta(days=1)       # a client clock a little behind
    not_after = not_before + datetime.timedelta(days=days)
    serial = int.from_bytes(secrets.token_bytes(16), 'big') >> 1 | 1   # positive, non-zero
    tbs = _seq(
        _tlv(0xa0, _int(2)),                                  # v3
        _int(serial),
        _SHA256_RSA,
        _name(common_name),
        _seq(_time(not_before), _time(not_after)),
        _name(common_name),
        public_key_der(key),
        _tlv(0xa3, _seq(
            _extension('2.5.29.19', _seq(), critical=True),                     # CA:FALSE
            _extension('2.5.29.15', b'\x03\x02\x05\xa0', critical=True),       # sign, encipher
            _extension('2.5.29.37', _seq(_oid('1.3.6.1.5.5.7.3.1'))),          # serverAuth
            _extension('2.5.29.17', _alt_names(dns_names, ips)),
        )),
    )
    return _seq(tbs, _SHA256_RSA, _tlv(0x03, b'\x00' + _sign(key, tbs)))


def private_key_der(key):
    """PKCS#1 RSAPrivateKey."""
    return _seq(_int(0), *[_int(key[k]) for k in ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qi')])


def pem(kind, der):
    body = base64.b64encode(der).decode('ascii')
    lines = [body[i:i + 64] for i in range(0, len(body), 64)]
    return '-----BEGIN %s-----\n%s\n-----END %s-----\n' % (kind, '\n'.join(lines), kind)

# -- reading a certificate back --------------------------------------------------


def _read_tlv(data, pos):
    tag = data[pos]
    size = data[pos + 1]
    pos += 2
    if size & 0x80:
        count = size & 0x7f
        size = int.from_bytes(data[pos:pos + count], 'big')
        pos += count
    return tag, data[pos:pos + size], pos + size


def _parse_time(tag, raw):
    text = raw.decode('ascii')
    if tag == 0x17:
        year = int(text[:2])
        text = ('19' if year >= 50 else '20') + text
    return datetime.datetime.strptime(text[:14], '%Y%m%d%H%M%S')


def validity(der):
    """(not_before, not_after) as naive UTC datetimes, from a DER
    certificate. Raises ValueError on anything that is not one."""
    try:
        _tag, cert, _ = _read_tlv(der, 0)
        _tag, tbs, _ = _read_tlv(cert, 0)
        pos = 0
        tag, _v, nxt = _read_tlv(tbs, pos)
        if tag == 0xa0:            # version present
            pos = nxt
        for _ in range(3):         # serial, signature, issuer
            _t, _v, pos = _read_tlv(tbs, pos)
        _t, val, _ = _read_tlv(tbs, pos)
        t1, raw1, p = _read_tlv(val, 0)
        t2, raw2, _ = _read_tlv(val, p)
        return _parse_time(t1, raw1), _parse_time(t2, raw2)
    except (IndexError, ValueError, UnicodeDecodeError) as e:
        raise ValueError('not an X.509 certificate: %s' % e)


def fingerprint(der):
    """SHA-256 as the browsers show it: AB:CD:..."""
    return ':'.join('%02X' % b for b in hashlib.sha256(der).digest())

# -- names for the certificate ----------------------------------------------------


_DNS_RE = re.compile(r'^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$')


def local_names(extra_host=''):
    """(common_name, dns_names, ips) for this computer. Best effort: a
    name that does not resolve just adds nothing."""
    host = socket.gethostname() or 'localhost'
    dns = []
    for name in (host, host.split('.')[0], 'localhost'):
        name = name.lower()
        if _DNS_RE.match(name) and len(name) <= 253 and name not in dns:
            dns.append(name)
    ips = ['127.0.0.1', '::1']
    candidates = [extra_host]
    try:
        candidates += [ai[4][0] for ai in socket.getaddrinfo(host, None)]
    except (OSError, UnicodeError):
        pass
    for ip in candidates:
        try:
            addr = ipaddress.ip_address((ip or '').split('%')[0])
        except ValueError:
            continue
        if not addr.is_unspecified and str(addr) not in ips and len(ips) < 20:
            ips.append(str(addr))
    return dns[0], dns, ips


def make(common_name, dns_names, ips, now=None, bits=KEY_BITS, days=VALID_DAYS):
    """(cert_pem, key_pem, cert_der) for a new self-signed certificate."""
    key = new_key(bits)
    der = certificate_der(key, common_name, dns_names, ips, now=now, days=days)
    return pem('CERTIFICATE', der), pem('RSA PRIVATE KEY', private_key_der(key)), der
