# CLAUDE.md

Uptime Sync 4 is a pure-Python rewrite of Uptime Sync 3.x. It has no PowerShell
or batch files and runs on Windows 7 to 11 (32- and 64-bit), Linux and macOS. It
talks to the same uptime-monitor server using the same heartbeat protocol (v1).
README.md covers usage. This file covers the rules for changing the code.

## Layout

- **Entry points:**
  - `main.py`: CLI (`uptime_sync/cli.py`).
  - `install.py`: venv bootstrap, then `main.py install`.
- **Process roles:**
  - `supervisor.py`: the process the OS starts.
  - `engine.py`: checks, pushes and heartbeat.
  - `web/`: Flask on waitress.
- **Monitoring:**
  - `checks.py`: PING, DNS, TCP and HTTP probes.
  - `monitors.py`: the model and validation.
  - `heartbeat.py` and `signing.py`: the protocol.
- **Updates:** `updater.py` handles the URL policy, download and stage (engine
  side) and swap and rollback (supervisor side).
  - The swap is all or nothing (`_swap`/`_undo`: each move is recorded as it
    happens, and the undo never raises). After it, `_smoke_test` imports the
    new code with the venv python; a build that cannot import is put back at
    once. A rollback that fails sets `RollbackFailed` so it is not retried on
    every child start.
  - A version is used in URLs and paths only when `util.is_version()` (exactly
    x.y.z) accepts it.
- **Durations use `time.monotonic()`** (check timings, loop sleeps, grace and
  backoff). Wall time only for timestamps and certificate expiry.
- **Autostart:** `autostart.py` (Task Scheduler XML, systemd, launchd).
- **Processes:** `procs.py` (pid, lock, popen flags).
- **Settings:** `settings.py` handles the overlay and `.env`.
  `importer.py` imports a 3.x install.
- **Logging:** `log.py` sets it up. `logstore.py` stores logs in SQLite.
- `paths.py` holds every path. `paths.SHIPPED` is both what an update swaps and
  what `tools/build-release.py` zips. Change it in one place only.

## Rules

- **Always `.venv`.** Agent processes run only on `<root>/.venv`
  (`paths.venv_python()` / `procs.background_python()`).
  - main.py re-launches itself there and refuses to run without it.
  - Never start the agent, pip or a child on `sys.executable` from outside
    `.venv`. install.py is the only system-Python script.
  - requirements.txt pins the full dependency tree, using environment markers
    where 3.8 and newer Pythons need different versions. After a bump, run
    `install.py --recreate` and `pip check` on 3.8 and on a current Python.
  - For development, `python3.8 install.py --no-autostart` gives this checkout
    a `.venv`. The unit tests run on any venv with the requirements; they do
    not go through main.py.
- **Python 3.8 floor.** Do not use:
  - `match`
  - 3.9+ APIs such as `str.removeprefix`, `dict | dict`, or builtin generics like
    `list[str]` in annotations that are evaluated at runtime
  - `zoneinfo`

  Run the tests on `.venv38` before you commit. Flask stays at 2.3.x and werkzeug
  at 3.0.x, because both still support 3.8.
- **ASCII only** in source and console strings. The Windows console is cp1252,
  and `pythonw` has no console at all.
- **Windows process facts:**
  - Never call `os.kill(pid, 0)`. It terminates the process on Windows. Use
    `procs.pid_alive`.
  - Background processes use `procs.background_python()` (pythonw.exe) and
    CREATE_NO_WINDOW.
  - Children get DEVNULL stdin and stdout. Their stderr goes to
    `logs/<name>-stderr.log`.
- **Exit codes are a contract.**
  - 0 means stopped on purpose, so the OS does not restart the agent.
  - `updater.EXIT_UPDATE` (3) means a verified build is staged.
  - `updater.EXIT_RESTART` (4) means the server asked for a restart.
  - `updater.EXIT_STUCK` (5) means a check hung for 3 intervals (4.0.8). The
    engine then leaves with `os._exit`: Python would wait for the hung pool
    thread for ever.
  - Anything else is a crash.
- **External programs go through `procs.run(cmd, timeout)`** (4.0.8): hidden
  window, stdout+stderr, hard timeout, never raises. No bare `subprocess.run`
  without a timeout anywhere in the agent.
- **One supervisor per folder.** The OS file lock in `procs.InstanceLock` decides
  this, not PID files. The Windows minute trigger relies on it.
- **Settings overlay.**
  - `data/settings.json` holds only the diff from `config/defaults.json`, so
    always save through `settings.save()` or `settings.update()`.
  - `.env`-managed values (`settings.ENV_SETTINGS`) are never written back to
    `settings.json` and never rendered into HTML.
  - `${NAME}` is expanded only in `monitors.runtime_view()`, which feeds the
    checker and never goes to the UI.
  - `settings.RESERVED_REFS` (the ENV_SETTINGS names + `UPTIME_SYNC_SECRET_KEY`)
    never expand and fail validation (4.0.8). A new agent credential in .env
    goes into that set.
  - Numbers listed in `settings.NUMERIC` are coerced and clamped by `load()`,
    so code may use `s['check_interval']` directly. Add a new numeric setting
    there.
- **Secrets.**
  - `secret_key` never appears in a payload, query string, header or log line.
    It signs, it does not travel.
  - Log URLs through `util.redact()`.
  - Write data files with `util.atomic_write_json(..., private=True)`.
  - Log a push URL, or an exception raised by a request to one, through
    `util.url_host()` only. The exception text carries the whole URL.
  - `perms.harden()` runs at every supervisor start, because applying
    permissions only when a file is created misses hand-made and restored
    files.
    - Windows: icacls by SID, inheritance removed. The install folder itself
      gets SYSTEM/Admins full control and Users read+execute only (4.0.6): it
      runs as SYSTEM every minute, and a folder made under C:\ inherits
      "Authenticated Users: Modify".
    - POSIX: 0700/0600, umask 077.
  - A new folder that holds secrets goes in `perms.PROTECTED`.
  - A CLI command run with sudo gives data/, logs/ and run/ back to
    `SUDO_UID` (`perms.return_to_sudo_user()`), because the service runs as
    that user.
- **Heartbeat protocol is additive-only.** The rules match 3.x:
  - Never remove or rename a field.
  - Every field has a default (`data.get(...)`).
  - Unknown fields are ignored.
  - Coordinate through capability strings, not version checks.
  - Bump `heartbeat.API_VERSION` only for a breaking change.
- **Reply signing.** `X-Response-Signature` is
  HMAC(secret, request X-Signature + "." + body).
  - `require_signed_response` can be true, false or "auto". With "auto", once a
    reply has been signed, unsigned replies are refused.
  - The latch fingerprint format is shared with 3.6.22 so an import keeps it.
  - Nothing from a reply that `may_act()` refuses is used, not even
    `next_check_in`. Replies are read with `stream=True`, at most
    `heartbeat.MAX_REPLY` decoded bytes and `READ_DEADLINE` seconds.
- **Update policy (`updater.resolve` / `check_redirect`).**
  - A GitHub URL must equal `github_url(repo, version)` exactly.
  - A GitHub redirect may only go to https `github.com` or
    `*.githubusercontent.com`.
  - A server URL is refused unless `update.allow_server_download` is true
    (4.0.8). That flag is set by hand only: never add it to the web form or to
    anything the heartbeat reply can change. With it on, the URL must be on the
    `remote.url` host, and an https server cannot hand out an http URL.
  - Redirects are followed by hand.
  - SHA-256 is mandatory and never bypassed, even by force_install.
  - The release must be newer than the installed version.
  - The zip is extracted with a zip-slip check.
  - The staged build must contain VERSION (equal to the offer), `main.py`,
    `uptime_sync/__init__.py` and `config/defaults.json`.
- **Web separation.**
  - Templates carry markup only: no inline `style=`, no `<script>`, no `on*=`
    handlers.
  - Behaviour lives in `static/app.js` through `data-*` attributes.
  - The CSP is `script-src 'self'`.
  - **Old browsers (4.0.4).** Windows 7 boxes open the UI in IE8-IE11 on the
    box itself. Every response sends `X-UA-Compatible: IE=edge`: without it IE
    renders localhost/LAN pages as IE7. In `app.css`, a `var(--x)` declaration
    follows the same property with the light-theme value, and flex, grid and
    gap live only inside `@supports (display: grid)`. The fallback outside uses
    floats, inline-block and margins. `app.js` is ES3: no fetch, arrow functions,
    const/let, classList, closest/matches, forEach/filter or innerHTML. It binds
    handlers per element (attachEvent fallback). Templates use `div` + `role`,
    not main/header/nav/footer/section. Pages must work with JS off.
    `OldBrowserTests` in tests/test_web.py checks all of this.
  - **Password eye (4.0.7).** app.js adds the show/hide button to every
    `input[type=password]` itself, so a new password field needs no markup.
    app.css hides the browsers' own buttons (`::-ms-reveal` in IE10+/Edge,
    Safari's key) or there are two eyes on top of each other. Each vendor
    pseudo-element gets a rule of its own: a browser drops a whole rule over
    one selector it does not know. No button where the type cannot be
    switched (IE8).
  - In templates, never write `x.update`, `x.items`, `x.keys` and the like for a dict
    key. Jinja finds the dict method first. Write `x['update']`
    (`DictMethodNameTests` enforces this).
  - **Light/dark (4.0.9).** Dark colours are defined twice in app.css: under
    `prefers-color-scheme: dark` as `:root:not([data-theme="light"])`, and as
    `:root[data-theme="dark"]`. Change a colour in both (`ThemeToggleTests`).
    `static/theme.js` (in `<head>`) sets `html[data-theme]` from localStorage
    `uptime-sync-theme`; app.js draws the toggle, but only where
    `CSS.supports('--x', '0')` holds.
  - **User menu (4.0.9).** `.user-menu` in base.html is a div, not
    `<details>`: IE8 cannot style unknown tags. Its base CSS is the old inline
    layout (the name links to Account, Sign out beside it). app.js adds `.js`
    and the dropdown look in `@supports` applies to `.user-menu.js` only.
    `.topbar` has `overflow: visible` inside `@supports`; otherwise it would
    clip the menu.
  - **Sign-in / setup layout (4.0.9).** Both pages use `main_class` `auth`,
    include `_auth_head.html` (logo, title, subtitle) and `_auth_foot.html`
    (version), and empty `{% block foot %}`. `.ver` is the version pill,
    shared with the top bar.
  - **Icons (4.0.9).** `web/icons.py` is the only source: `{{ icon('name') }}`
    (a Jinja global) prints the inline SVG for IE9+ and, in a `lt IE 9`
    conditional comment, a `.ic8-name` cell of `static/icons-ie8.png`. A new
    or changed icon means: add it to `PATHS`, rebuild the PNG with
    `tools/ie8-icons.py` (open its page in a browser, save the PNG), and paste
    `icons.ie8_css()` into app.css. `IconTests` checks the PNG width, the CSS
    offsets and that templates name only known icons. The `--*-ink` colours
    also live in both dark blocks.
  - **Phones (4.0.9).** A `table.stack` becomes one small card per row below
    640px. Give its cells a role: `title` (the name, first line), `lead` (the
    status, right of the name), `wide` (a line of its own), or a `data-label`
    that is printed before the value. The dashboard rows that app.js redraws
    need the same classes and labels (`PhoneLayoutTests`). These rules sit
    inside `@supports`, so IE keeps the plain table.
  - Every POST carries the `csrf` form field.
  - Admin-only routes use `@auth.admin_required`.
  - Any form that checks a password calls `auth.begin_attempt(key)` before
    hashing (sign-in: the IP; Account: `account:<name>`), and
    `clear_failures(key)` on success.
  - Dashboard tile words come from `views.tile_text()` (colours from
    `tones()`), for the template and app.js alike. Never word them in JS.
  - A viewer never sees a push token. Use `mask_push_url`.
- **Logs.**
  - Use `logging.getLogger(<name>)` everywhere. `log.setup(proc)` routes it to
    `logs/logs.db`, written from one thread per process in batches.
  - Never log from inside `logstore`'s writer path.
  - The Logs page goes through `logstore.page()`: a text search reads at
    most `SEARCH_SPAN` ids per page (LIKE cannot use an index). SQLite reads
    `min(id)` or `max(id)` off the b-tree only when it is alone in a SELECT:
    together they scan (see `_ID_RANGE_SQL`). Check a new query with
    EXPLAIN QUERY PLAN on a million rows.
  - Do not use `app.logger`: Flask gives it its own stderr handler.
  - **Levels (4.0.9) live in `loglevel.py` only.** `log_level` is the global
    level; `log_levels` = `{part: level}` overrides it per part, where a part
    is a logger name from `loglevel.COMPONENTS` (`libraries` = urllib3,
    waitress, werkzeug, WARNING unless set, and never below INFO:
    urllib3's DEBUG line is the request URL with the push token in it;
    `loglevel.choices(part)` is what a part may be set to). A new `getLogger('x')` needs an
    entry in COMPONENTS, or `LogLevelTests` fails. Never write a list of
    level names elsewhere: use `loglevel.LEVELS` / `normalize()` / `VALUES`.
  - `settings.load()` cleans both keys (`loglevel.coerce`), so readers see
    valid values. Every process applies them with `loglevel.apply()` via
    `log.setup()`, CLI commands via `log.setup_console()` (stderr, not
    logs.db). Long-running loops call `loglevel.refresh()`, which stats
    settings.json at most every 2 s, so a saved level reaches the supervisor,
    engine and web without a restart. The Settings page replaces
    `log_levels` whole (`settings.update` merges and could never drop an
    override). The server's `settings.log_level` sets the global level only.
- **Self-healing (4.0.8).**
  - `util.read_json()` heals by default: a file that exists but does not parse
    is moved to `<file>.corrupt-<ts>` (3 kept), logged CRITICAL, and restored
    from `<file>.bak` when that parses. Pass `heal=False` only for files the
    agent must not move (3.x files in `importer`, `config/defaults.json`).
  - Files that must survive corruption are written with `backup=True`
    (settings, monitors, users). The `.bak` is taken only from a file that parses.
  - `auth.has_users()` stays True when users.json is unreadable or was
    quarantined, so `/setup` never reopens. `main.py reset-password` is the fix.
  - logs.db: `logstore.quarantine()` replaces a corrupt database, and
    `prune()` enforces `LOG_DB_MAX_BYTES`. A PRAGMA that returns rows does its
    work only when they are read: always `.fetchall()` it.
  - Every log writer checks `logstore.identity()` (st_dev, st_ino) before a
    batch and reopens when logs.db was moved away: on POSIX an open SQLite
    connection keeps writing into the renamed file. On Windows the move fails
    while others have it open, so `quarantine()` writes `logs.db.reset`
    naming the corrupt file's identity; each writer then closes and tries the
    move itself. A flag naming another file is stale and removed, never acted
    on. Prune deletes in `DELETE_CHUNK` transactions.
  - `log.setup()` and the engine's `_housekeeping()` never raise.
  - `updater.apply()` writes status `Applying` before the first move, and
    `updater.recover_interrupted()` runs at every supervisor start, right after
    the lock. Every move out happens before any move in. Keep that order, because
    recovery relies on it to tell old files from new ones.
  - The supervisor restarts an engine whose `run/status.json` has not changed
    for 3 x check_interval + 60 s, timed by `time.monotonic()` (never compare
    an mtime with `time.time()`: w32time steps the clock). The engine must keep
    writing it every cycle, and touches it when the write fails (full disk).
  - EXIT_STUCK (5) is the engine curing a hung check: restart in 1 s, no
    crash count, no backoff.
  - The supervisor loop body is `_tick()`, wrapped so one exception is logged
    (at most once a minute) and the loop goes on: the supervisor exiting
    stops every healthy child. Children are started by `_tick()`, and a
    failed Popen gets the normal backoff.
  - A new version is rolled back after `UPDATE_MAX_CRASHES` engine crashes,
    or when its supervisor starts more than that many times while the state
    is still `Applied` (`supervisor_starts`, reset by `apply()`).
  - `log.setup()` sets `threading.excepthook`, so a dying thread is logged.
  - `time.monotonic()` can start near 0 in a new process: never use 0.0 as
    "long ago" in a throttle; use None.
  - The engine restarts itself (EXIT_STUCK) when one heartbeat has been in
    flight for `HEARTBEAT_STUCK_SECONDS`. So nothing slow may run on the
    heartbeat or watch thread: an install goes through `_start_install()`.
  - `monitors.load(strict=True)` raises on a file that exists but cannot be
    read; the engine then keeps its monitors. Use `read_json(strict=True)`
    wherever "unreadable for a moment" must not mean "empty".
- **Reporting server URL (4.0.9).** `remote.url` is the Public URL and
  `remote.local_url` is the Local one. Always read the URL in use through
  `util.active_server_url(remote)`: heartbeat, signing latch and updater all do.
  Every request to it passes `verify=util.server_tls_verify(remote)`. It is False only when
  `server_type` is "local" AND `util.is_local_host()` holds right now. That check
  is repeated on every call, never cached in settings. GitHub is always verified.
  "Local" means `util.LOCAL_NETWORKS`, an explicit list: never
  `ipaddress.is_private`, which also covers internet-routed ranges.
- **Numeric limits have one table each.** Settings: `settings.NUMERIC`
  (`settings.BOUNDS` for the form); monitors: `monitors.LIMITS`. load() and
  normalize() clamp hand-edited files; the forms take their min/max and their
  checks from the same table and reject, never clamp, what is outside it.
- **Supervisor start order.** The lock, then the stopped flag, then everything
  else. The Windows minute trigger starts a copy every minute, so nothing heavy
  may come before the lock (updater imports `requests` lazily for this reason).
- **Autostart names** are per install: the default name is used, unless an existing
  task, unit or plist starts another folder's main.py. In that case the install gets
  `<name>-<sha1(root)[:8]>`. Uninstall and start use the name kept in
  data/autostart.json.
- **Log volume.** A push that succeeds with no change from the last one logs
  at DEBUG. INFO is for changes and WARNING for errors. A failure that repeats
  unchanged logs at DEBUG, with a WARNING reminder every
  `PUSH_REMINDER_SECONDS` (`engine._log_push`). One line per push. Keep it
  that way for new per-cycle messages.
- **VERSION is prepend-only.** Never edit or remove older entries.

## Testing

- **Unit tests:** `.venv38/bin/python -m unittest discover -s tests -t .` (also run
  them on a current Python). `tests/_env.py` points `UPTIME_SYNC_ROOT` at a temp
  copy. Import it first in every test module.
- **Lint:** `python -m pyflakes uptime_sync tests main.py install.py tools`.
- **End-to-end:**
  1. Copy the shipped files to a scratch folder.
  2. Point `remote.url` at a local fake server that signs replies.
  3. Run `main.py start`.
  4. Check the pushes and heartbeats, kill the engine, and offer a forced update
     and a broken update.

  This is how 4.0.0 was verified: update, then rollback after three crashes.
  `tests/test_engine.py` covers the agent refusing to retry a failed version.
