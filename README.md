# Uptime Sync 4

A small agent that checks your network from the inside (PING, DNS, TCP port,
HTTP/HTTPS) and pushes each result to an Uptime Kuma push monitor. It also
sends a signed heartbeat to an **uptime-monitor** server, which can show the box's
health, push a log level, ask for a restart, and roll out updates.

Pure Python. It runs on **Windows 7 to 11 (32- or 64-bit)**, **Linux** and **macOS**,
needs **Python 3.8 or newer**, and starts by itself at boot.

## Install

Copy (or unzip) this folder somewhere permanent, then run the installer with the
system Python:

| OS | Command | Autostart |
|---|---|---|
| Windows | Double-click `install.bat` (it asks for administrator rights), or `py -3 install.py` from an **elevated** prompt | Task Scheduler task `UptimeSync4` (at boot, plus every minute as a watchdog), runs as SYSTEM |
| Linux | `sudo python3 install.py` | systemd unit `uptime-sync.service`. Without sudo it creates a user unit instead |
| macOS | `sudo python3 install.py` | LaunchDaemon `com.uptimesync.agent`. Without sudo it creates a LaunchAgent that runs only while you are logged in |

`install.py` creates `.venv/` in the folder and installs `requirements.txt` into it.
Every pinned package, dependencies included, goes there. After that, everything
runs on `.venv`'s Python. You can type `python main.py ...` with any Python:
main.py restarts itself inside `.venv`. The system Python is used only to create
`.venv`.

`.venv` still uses the system Python's standard library. If you uninstall or
upgrade that Python, run `python main.py stop`, then `python install.py --recreate`
(it refuses while the agent is running), then `python main.py start`.
It then registers autostart and starts the agent. Open `http://<box>:5000/` and
create the admin account.

`install.bat` finds the system Python (`py -3`, then `python`), checks it is 3.8 or
newer, runs `install.py` with it and keeps the window open so you can read the result.
Options are passed through: `install.bat --no-autostart`, `--recreate`, `--wheels C:\wheels`.

For an offline install, run `install.py --wheels <folder of .whl files>`. On Windows 7,
use Python 3.8.10, the last release that supports it.

### Coming from Uptime Sync 3.x

Stop the old install for good first. Both versions would push the same monitors,
and both want port 5000. On Windows that means running
`scripts\service-manager.ps1 -StopService` and deleting its scheduled tasks. Then:

```
python main.py import "C:\path\to\old\uptime-sync" --dry-run    # look first
python main.py import "C:\path\to\old\uptime-sync"
python main.py install
```

The import carries over:

- the server URL, api_key and HMAC secret
- the site name and intervals
- the monitors and their push URLs
- `data/.env`
- the web users and their passwords
- the response-signing latch

It never modifies the old folder.

## Commands

```
python main.py status            what is running (exit 3 when not running)
python main.py start | stop | restart
python main.py check             run every monitor once and print the result (no push)
python main.py logs -n 200 --level WARNING --proc engine --grep timeout
python main.py reset-password [user]    locked out? set a new password here
python main.py import <3.x folder> [--dry-run] [--force]
python main.py install [--no-autostart] | uninstall
python main.py version          (or --version, -v)
python main.py help [command]    the list above, or every option of one command
```

A command also works with a dash or slash in front (`-restart`, `--restart`,
`/restart`). On Windows `main.py /?` works too. In zsh `?` is a wildcard, so
type `help`.

`stop` is sticky. It writes `run/stopped`, so neither the watchdog nor a reboot
brings the agent back until you run `start`.

## How it runs

```
OS autostart -> main.py run (supervisor, one per folder: OS file lock)
                  |- main.py engine   checks, pushes, heartbeat, downloads updates
                  '- main.py web      the web UI (waitress, port 5000)
```

The supervisor restarts a child that dies, with a backoff of 1, 2, 5, 10, 30 and
60 s. It applies updates and rolls them back.

- **Exit codes:** 0 means "stopped on purpose", so the OS leaves the agent alone.
  Any other exit is a crash, and the OS restarts it.
- **Logs:** they go to `logs/logs.db` (SQLite). The web UI's Logs page and
  `main.py logs` read them there.
- **Text logs:** two kinds appear only when something went wrong.
  - `logs/<proc>-stderr.log` holds output from a process that crashed before it
    could log.
  - `logs/fallback-<date>.log` holds lines the database could not take.

It repairs itself where it can:

- **Damaged data files:** a JSON file that does not parse is moved to
  `<file>.corrupt-<time>` and logged at CRITICAL. settings, monitors and users
  come back from their `.bak` (the last good version). If the user accounts
  are lost, run `main.py reset-password` on the box.
- **logs.db:** a damaged database is moved aside and a new one started. The file
  stays under 200 MB, and with little disk space left only 3 days are kept.
- **Interrupted update:** a power cut during an install puts the previous
  version back on the next start.
- **Hung engine:** a check stuck for 3 intervals, or an engine that stops
  finishing its cycles, gets the engine restarted.

## Permissions

`data/` holds the secrets and `logs/` holds the history. On every start, the agent makes both folders readable only by the service account and the admin who ran `install`.

- **Windows:** inheritance is removed, and only SYSTEM, Administrators and the installing user get access.
- **Linux / macOS:** folders are set to 0700 and files to 0600.

`main.py status` lists anything that other users can still read.

On Windows, put the folder somewhere like `C:\UptimeSync4`, not under a user profile.

## Settings

| Path | What | Updates |
|---|---|---|
| `config/defaults.json` | shipped defaults | replaced on update |
| `data/settings.json` | what this site changed (the web UI writes it) | never touched |
| `data/.env` | secrets, from the template `config/env.example`. Overrides `UPTIME_API_KEY`, `UPTIME_SECRET_KEY`, `UPTIME_REMOTE_URL`, and any `${NAME}` used in a push URL | never touched |
| `data/monitors.json`, `data/users.json` | edited through the web UI | never touched |

Precedence is: OS environment > `data/.env` > `data/settings.json` > defaults.

**Server location** (Settings > Reporting): Public and Local network each have
their own URL. Heartbeats go to the URL of the chosen one.
- *Public* (`remote.url`) always checks the server's certificate.
- *Local network* (`remote.local_url`) also accepts http and a self-signed https
  certificate. It is allowed only for localhost and private or LAN addresses, for
  example `http://192.168.1.10/uptime-monitor/api/heartbeat.php`.

## Updates

uptime-monitor decides **when** to update: the update mode and window, the
rollout queue, and Force Update. Its signed heartbeat reply carries the version
and the zip's SHA-256. The agent downloads the zip from this repository's GitHub
release:

```
https://github.com/chuwa22/uptime-sync-v4/releases/download/v<ver>/uptime-sync-v<ver>.zip
```

Before installing, the agent checks the download:

- The URL must be exactly that asset of the configured repository.
- A download from the uptime-monitor host itself (the 3.x way) is refused unless
  `"update": {"allow_server_download": true}` is set by hand in
  `data/settings.json`. The web UI cannot set it: whoever can change the server
  address there could otherwise hand the agent a zip of their own.
- Redirects are checked hop by hop.
- The SHA-256 is mandatory.
- The release must be newer than the installed version.
- The zip contents must pass a safety check.

When the checks pass, the supervisor swaps the new version in and keeps the old
one in `backups/`. If the new engine crashes three times before it has run for
five minutes, the supervisor puts the old version back. A version that failed on
a box is not retried there unless an admin uses Force Update.

## Development

```
python -m unittest discover -s tests -t .      # also on Python 3.8: .venv38/bin/python ...
git config core.hooksPath tools/git-hooks      # once per clone: keeps data/ and secrets out of git
python tools/build-release.py                  # dist/uptime-sync-v<ver>.zip + .sha256
python tools/build-release.py --publish        # GitHub release v<ver> (needs gh, pushed HEAD)
```

Bump the version by prepending a block to `VERSION`. Never edit or remove older
entries.

## License

MIT -- see [LICENSE](LICENSE).
