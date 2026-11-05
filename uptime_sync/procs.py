"""Process helpers that work the same on Windows, Linux and macOS.

Never call os.kill(pid, 0) on Windows to test a PID: there it is
TerminateProcess and kills the target.
"""

import os
import subprocess
import sys

IS_WINDOWS = sys.platform.startswith('win')


def pid_alive(pid):
    try:
        pid = int(pid)
    except (TypeError, ValueError):
        return False
    if pid <= 0:
        return False
    if IS_WINDOWS:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        handle = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not handle:
            return ctypes.get_last_error() == 5  # access denied -> it exists
        try:
            code = wintypes.DWORD()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return False
            return code.value == 259  # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def read_pid(path):
    try:
        with open(path, 'r') as f:
            return int(f.read().strip() or 0)
    except (OSError, ValueError):
        return 0


def write_pid(path, pid=None):
    """Atomic. False (never an exception) when run/ cannot be written: a PID
    file is a convenience for `status`, not a reason for a process to die."""
    from .util import atomic_write_text
    try:
        atomic_write_text(path, str(pid or os.getpid()))
        return True
    except OSError:
        return False


def run(cmd, timeout, cwd=None):
    """Run a helper program hidden, with a hard timeout.

    Returns (returncode, output_bytes, error): stdout+stderr together;
    returncode is None when the program could not start (error = why) or
    ran past `timeout` seconds (error = 'timed out after Ns', the child is
    killed). Every external program the agent runs goes through here, so
    none of them can hang a process forever."""
    flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0) if IS_WINDOWS else 0
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           stdin=subprocess.DEVNULL, timeout=timeout, cwd=cwd, creationflags=flags)
    except subprocess.TimeoutExpired as e:
        return None, e.output or b'', 'timed out after %ds' % timeout
    except (OSError, ValueError, subprocess.SubprocessError) as e:
        return None, b'', str(e)
    return p.returncode, p.stdout or b'', ''


def background_python():
    """The interpreter for an agent process with no console window: always
    <root>/.venv's (pythonw.exe on Windows), never the system Python, so
    the agent only ever sees the packages installed in .venv."""
    from . import paths
    exe = paths.venv_python(background=True)
    if os.path.isfile(exe):
        return exe
    # .venv without pythonw.exe (should not happen): its console python.
    return paths.venv_python()


def child_popen_kwargs():
    """Popen kwargs for a supervised child: no window, no inherited stdio."""
    kw = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL,
          'close_fds': True}
    if IS_WINDOWS:
        kw['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0x08000000) | \
            getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x200)
    return kw


def detached_popen_kwargs():
    """Popen kwargs for a process that must outlive its parent."""
    kw = {'stdin': subprocess.DEVNULL, 'stdout': subprocess.DEVNULL, 'stderr': subprocess.DEVNULL,
          'close_fds': True}
    if IS_WINDOWS:
        kw['creationflags'] = 0x00000008 | 0x00000200  # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw['start_new_session'] = True
    return kw


class InstanceLock:
    """Exclusive, non-blocking lock on a file; released when the process
    dies, however it dies. The OS lock is the truth, not the file's content."""

    def __init__(self, path):
        self.path = path
        self._f = None

    def acquire(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        f = open(self.path, 'a+')
        try:
            if IS_WINDOWS:
                import msvcrt
                f.seek(0)
                msvcrt.locking(f.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            f.close()
            return False
        self._f = f
        return True

    def release(self):
        if not self._f:
            return
        try:
            if IS_WINDOWS:
                import msvcrt
                self._f.seek(0)
                msvcrt.locking(self._f.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                import fcntl
                fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
        except OSError:
            pass
        self._f.close()
        self._f = None

    def held_by_other(self):
        """True if another process holds the lock right now."""
        if self._f:
            return False
        if self.acquire():
            self.release()
            return False
        return True
