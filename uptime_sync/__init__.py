"""Uptime Sync 4 -- network uptime agent for Uptime Kuma / uptime-monitor.

Python 3.8+ (3.8 is what Windows 7 SP1 32-bit can run), stdlib plus
requests / flask / waitress. Console-facing strings stay ASCII: the Windows
console and pythonw's redirected streams are cp1252.
"""

import os


def _read_version():
    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'VERSION')
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return f.readline().strip() or '0.0.0'
    except (OSError, ValueError):
        return '0.0.0'


__version__ = _read_version()
