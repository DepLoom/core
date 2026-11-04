"""Linux owned process closure via a private PID namespace and an init pidfd."""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import signal
import sys
import time


_UNSHARE = Path("/usr/bin/unshare")
_LAUNCHER_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
_NAMESPACE_FLAGS = ("--user", "--map-current-user", "--pid", "--fork", "--mount-proc", "--kill-child=SIGKILL")
_BOOTSTRAP = """\
import ctypes
import json
import os
import sys

ready, gate = map(int, sys.argv[1:])
if os.getpid() != 1 or ctypes.CDLL(None).prctl(38, 1, 0, 0, 0) != 0:
    raise SystemExit(125)
os.write(ready, b"1")
os.close(ready)
with os.fdopen(gate, "rb") as stream:
    raw = stream.read()
if not raw:
    raise SystemExit(125)
argv, environment = json.loads(raw)
os.execvpe(argv[0], argv, environment)
"""


class LinuxPidNamespaceError(RuntimeError):
    pass


def linux_pid_namespace_available() -> bool:
    return (sys.platform == "linux" and _UNSHARE.is_file()
            and hasattr(os, "pidfd_open") and hasattr(signal, "pidfd_send_signal")
            and Path("/proc/self/ns/pid").exists())


class LinuxPidNamespace:
    """Gate command exec until the parent has verified and pinned namespace init."""

    def __init__(self, argv, environment):
        self.payload = json.dumps([list(argv), dict(environment)]).encode("ascii")
        if len(self.payload) > 256 * 1024:
            raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_LAUNCH_TOO_LARGE")
        self.ready_read = self.ready_write = self.gate_read = self.gate_write = self.pidfd = None

    def launch(self, options):
        self.ready_read, self.ready_write = os.pipe()
        self.gate_read, self.gate_write = os.pipe()
        options["env"] = _LAUNCHER_ENV
        options["pass_fds"] = (self.ready_write, self.gate_read)
        return [str(_UNSHARE), *_NAMESPACE_FLAGS, "--", sys.executable, "-I", "-B", "-c", _BOOTSTRAP,
                str(self.ready_write), str(self.gate_read)]

    def attach(self, process, deadline):
        self._close("ready_write")
        self._close("gate_read")
        wait = select.poll()
        wait.register(self.ready_read, select.POLLIN)
        remaining_ms = int(1000 * max(0, min(5.0, deadline - time.monotonic())))
        if not wait.poll(remaining_ms) or os.read(self.ready_read, 1) != b"1":
            raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_INIT_UNAVAILABLE")
        self._close("ready_read")
        children = Path(f"/proc/{process.pid}/task/{process.pid}/children").read_text().split()
        if len(children) != 1 or not children[0].isdigit():
            raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_CHILD_UNPROVEN")
        pid = int(children[0])
        self.pidfd = os.pidfd_open(pid)
        child_proc = Path(f"/proc/{pid}")
        status = dict(line.split(":", 1) for line in (child_proc / "status").read_text().splitlines() if ":" in line)
        if (status.get("NSpid", "").split()[-1:] != ["1"]
                or status.get("PPid", "").strip() != str(process.pid)
                or status.get("NoNewPrivs", "").strip() != "1"
                or (child_proc / "ns/pid").stat().st_ino == Path("/proc/self/ns/pid").stat().st_ino):
            raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_CHILD_UNPROVEN")
        if deadline <= time.monotonic():
            raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_LAUNCH_TIMEOUT")
        gate = self.gate_write
        os.set_blocking(gate, False)
        writable = select.poll()
        writable.register(gate, select.POLLOUT)
        payload = memoryview(self.payload)
        while payload:
            remaining_ms = int(1000 * max(0, deadline - time.monotonic()))
            if not remaining_ms or not writable.poll(remaining_ms):
                raise LinuxPidNamespaceError("LINUX_PID_NAMESPACE_LAUNCH_TIMEOUT")
            try:
                payload = payload[os.write(gate, payload):]
            except BlockingIOError:
                continue
        self._close("gate_write")

    def terminate(self):
        if self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, signal.SIGKILL)
            except ProcessLookupError:
                pass

    def closed(self, timeout_seconds):
        if self.pidfd is None:
            return False
        wait = select.poll()
        wait.register(self.pidfd, select.POLLIN)
        return any(event & select.POLLIN for _, event in wait.poll(int(timeout_seconds * 1000)))

    def _close(self, name):
        fd = getattr(self, name)
        if fd is not None:
            setattr(self, name, None)
            os.close(fd)

    def cleanup(self, process):
        try:
            if self.pidfd is not None and not self.closed(0):
                self.terminate()
                self.closed(3)
            if process is not None and process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        finally:
            self.close()

    def close(self):
        for name in ("ready_read", "ready_write", "gate_read", "gate_write", "pidfd"):
            self._close(name)
