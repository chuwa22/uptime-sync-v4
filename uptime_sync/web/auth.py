"""Users (data/users.json) and login sessions.

users.json: {"<username>": {"password": "<salt>$<iterations>$<hex>", "role":
"admin", "created_at": ..., "last_login": ..., "is_active": true,
"epoch": 1}} -- the same password format as Uptime Sync 3.x, so `import`
keeps every login. Changing a password bumps `epoch`, which invalidates
every session issued before it (the session cookie carries the epoch).
"""

import functools
import hashlib
import hmac
import os
import secrets
import threading
import time

from flask import abort, g, redirect, request, session, url_for

from .. import paths
from ..util import atomic_write_json, corrupt_copies, iso_now, read_json, touch

ITERATIONS = 600000
LEGACY_ITERATIONS = 100000
MIN_PASSWORD = 12
ROLES = ('admin', 'viewer')

_lock = threading.Lock()
_attempts = {}            # key (ip, or 'account:<user>') -> [timestamps]
MAX_ATTEMPTS = 10
ATTEMPT_WINDOW = 300
MAX_TRACKED = 2000        # keys kept; IPv6 makes new source addresses cheap
# 600k PBKDF2 rounds cost about 0.5 s of CPU each (more on a Win7 Atom):
# at most two at a time, whatever the number of waitress threads.
_hash_slots = threading.BoundedSemaphore(2)


def hash_password(password, iterations=ITERATIONS):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return '%s$%d$%s' % (salt, iterations, digest.hex())


def check_password(password, stored):
    """True if password matches. Accepts 3.x's legacy 'salt$hex' (100k)."""
    parts = str(stored or '').split('$')
    if len(parts) == 3:
        salt, iterations, expected = parts[0], parts[1], parts[2]
    elif len(parts) == 2:
        salt, iterations, expected = parts[0], LEGACY_ITERATIONS, parts[1]
    else:
        return False
    try:
        iterations = int(iterations)
    except ValueError:
        return False
    if not 1 <= iterations <= 10 * ITERATIONS:
        return False     # a hand-edited users.json must not hang the web UI
    with _hash_slots:
        digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt.encode('utf-8'), iterations)
    return hmac.compare_digest(digest.hex(), expected)


def load_users():
    data = read_json(paths.USERS_FILE, {}) or {}
    if not isinstance(data, dict):
        return {}
    return {k: v for k, v in data.items() if isinstance(v, dict) and not k.startswith('_')}


def save_users(users):
    # mirror: .bak never holds an old password hash, a deleted user or the
    # epoch before a sign-out-everywhere (util.atomic_write_json)
    atomic_write_json(paths.USERS_FILE, users, private=True, backup='mirror')


def has_users():
    """True once an admin was ever created -- also when users.json cannot be
    read, or was corrupt and quarantined with no usable backup. Otherwise
    /setup would reopen and whoever reached it first would become admin.
    `main.py reset-password` on the box is the way back in."""
    return bool(load_users()) or os.path.exists(paths.USERS_FILE) or \
        bool(corrupt_copies(paths.USERS_FILE))


def accounts_lost():
    """has_users() is True but there is no account to sign in with."""
    return has_users() and not load_users()


def create_user(username, password, role='admin'):
    with _lock:
        users = load_users()
        if username in users:
            raise ValueError('That user already exists.')
        users[username] = {'password': hash_password(password), 'role': role,
                           'created_at': iso_now(), 'last_login': None, 'is_active': True,
                           'epoch': 1}
        save_users(users)


def set_password(username, password):
    with _lock:
        users = load_users()
        user = users[username]
        user['password'] = hash_password(password)
        user['epoch'] = int(user.get('epoch', 1)) + 1
        save_users(users)
        return user['epoch']


def revoke_sessions(username):
    """End every session of this user. Sessions live in the signed cookie, so
    clearing it on sign-out is not enough: a copied cookie (plain http on a
    LAN) would keep working. Bumping the epoch makes all of them stale. It
    also signs the user out on their other browsers, which is the safe
    reading of "Sign out" for an admin UI."""
    with _lock:
        users = load_users()
        if username in users:
            users[username]['epoch'] = int(users[username].get('epoch', 1)) + 1
            save_users(users)


def canonical_name(username):
    """The stored spelling of a username typed in any case ('Admin' finds
    'admin'; 3.x users imported as 'ADMIN' still log in as 'admin'). An
    exact match wins; an ambiguous one (two users differing only in case)
    is left as typed."""
    users = load_users()
    if username in users:
        return username
    hits = [n for n in users if n.lower() == username.lower()]
    return hits[0] if len(hits) == 1 else username


def authenticate(username, password):
    """The user dict on success, else None. Upgrades old hashes in place."""
    users = load_users()
    user = users.get(username)
    if not user or not user.get('is_active', True):
        # Spend the same time as a real check so usernames cannot be probed.
        check_password(password, '00$%d$00' % ITERATIONS)
        return None
    if not check_password(password, user.get('password')):
        return None
    with _lock:
        users = load_users()
        user = users[username]
        if not str(user.get('password', '')).count('$') == 2 or \
                str(user['password']).split('$')[1] != str(ITERATIONS):
            user['password'] = hash_password(password)
        user['last_login'] = iso_now()
        user.setdefault('epoch', 1)
        save_users(users)
    return user


def password_problem(password, confirm=None):
    if len(password or '') < MIN_PASSWORD:
        return 'Password must be at least %d characters.' % MIN_PASSWORD
    if confirm is not None and password != confirm:
        return 'The two passwords do not match.'
    return ''


def rate_limited(ip):
    now = time.time()
    with _lock:
        recent = [t for t in _attempts.get(ip, []) if now - t < ATTEMPT_WINDOW]
        if recent:
            _attempts[ip] = recent
        else:
            _attempts.pop(ip, None)   # do not keep one empty entry per IP ever seen
        return len(recent) >= MAX_ATTEMPTS


def note_failure(ip):
    with _lock:
        _attempts.setdefault(ip, []).append(time.time())
        _trim()


def begin_attempt(key):
    """Count a password attempt BEFORE the hash is checked; False when
    `key` is over the limit. Counting afterwards (rate_limited, then
    note_failure) let parallel requests that all passed the check through
    together. A successful sign-in calls clear_failures(key)."""
    now = time.time()
    with _lock:
        recent = [t for t in _attempts.get(key, []) if now - t < ATTEMPT_WINDOW]
        if len(recent) >= MAX_ATTEMPTS:
            _attempts[key] = recent
            return False
        recent.append(now)
        _attempts[key] = recent
        _trim()
        return True


def _trim():
    """Keep _attempts bounded (caller holds _lock): expired keys first,
    then the ones whose last attempt is oldest."""
    if len(_attempts) <= MAX_TRACKED:
        return
    now = time.time()
    for key in [k for k, v in _attempts.items() if not v or now - v[-1] >= ATTEMPT_WINDOW]:
        del _attempts[key]
    if len(_attempts) > MAX_TRACKED:
        for key in sorted(_attempts, key=lambda k: _attempts[k][-1])[:len(_attempts) - MAX_TRACKED]:
            del _attempts[key]


def clear_failures(ip):
    with _lock:
        _attempts.pop(ip, None)


def login(username, user):
    session.clear()
    session['user'] = username
    session['epoch'] = int(user.get('epoch', 1))
    session['csrf'] = secrets.token_urlsafe(32)
    session.permanent = True


def current_user():
    """(username, user dict) of the logged-in user, or (None, None).
    A deleted user, a disabled one or a stale epoch logs the session out."""
    if 'user_cache' in g:
        return g.user_cache
    name = session.get('user')
    result = (None, None)
    if name:
        user = load_users().get(name)
        if user and user.get('is_active', True) and int(user.get('epoch', 1)) == session.get('epoch'):
            result = (name, user)
        else:
            session.clear()
    g.user_cache = result
    return result


def csrf_token():
    if 'csrf' not in session:
        session['csrf'] = secrets.token_urlsafe(32)
    return session['csrf']


def check_csrf():
    sent = request.form.get('csrf') or request.headers.get('X-CSRF-Token') or ''
    # Compare bytes: compare_digest raises TypeError on non-ASCII str (-> 500).
    if not session.get('csrf') or not hmac.compare_digest(sent.encode('utf-8'),
                                                          session['csrf'].encode('utf-8')):
        abort(400, 'Invalid or missing CSRF token - reload the page and try again.')


def login_required(view):
    @functools.wraps(view)
    def wrapper(*args, **kwargs):
        name, _ = current_user()
        if not name:
            if request.path.startswith('/api/'):
                abort(401)
            return redirect(url_for('login', next=request.path))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @functools.wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        _, user = current_user()
        if (user or {}).get('role', 'admin') != 'admin':
            abort(403)
        return view(*args, **kwargs)
    return wrapper


def client_ip():
    # Behind no proxy by design: a LAN tool. X-Forwarded-For is not trusted.
    return request.remote_addr or '?'


def app_secret_key():
    """data/secret.key, created on first use (UPTIME_SYNC_SECRET_KEY in
    data/.env or the environment overrides it)."""
    from .. import settings
    env = settings.env_values().get('UPTIME_SYNC_SECRET_KEY')
    if env:
        return env
    try:
        with open(paths.SECRET_KEY_FILE, 'r', encoding='utf-8') as f:
            key = f.read().strip()
            if len(key) >= 32:
                return key
    except OSError:
        pass
    key = secrets.token_hex(32)
    touch(paths.SECRET_KEY_FILE, key)
    if os.name != 'nt':
        try:
            os.chmod(paths.SECRET_KEY_FILE, 0o600)
        except OSError:
            pass
    return key
