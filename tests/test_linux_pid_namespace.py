"""Native controls for the optional Linux owned-tree backend."""
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from verification_linux_pid_namespace import linux_pid_namespace_available
from verification_process_supervisor import ProcessSupervisionError, run_supervised


@unittest.skipUnless(sys.platform == "linux" and linux_pid_namespace_available(), "Linux PID namespace tools required")
class LinuxPidNamespaceTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def supervise(self, body, timeout=8):
        return run_supervised([sys.executable, "-I", "-B", "-c", body], self.root,
                              timeout_seconds=timeout, require_guaranteed_tree=True)

    def test_exit_status_and_isolated_pid(self):
        result = self.supervise("import os, sys; print(os.getpid(), flush=True); sys.exit(7)")
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout.strip(), "1")
        self.assertEqual(result.supervision.quality, "guaranteed-tree")
        self.assertTrue(result.supervision.attach_before_execution)

    def detached(self, parent_stays_alive):
        child = ("from pathlib import Path; import time; Path('started').write_text('ready'); "
                 "time.sleep(1.4); Path('escaped').write_text('unexpected')")
        return (
            "import os, subprocess, sys, time; from pathlib import Path\n"
            "assert os.getpid() == 1\n"
            f"subprocess.Popen([sys.executable, '-I', '-B', '-c', {child!r}], env={{}}, "
            "start_new_session=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            "deadline=time.monotonic()+0.5\n"
            "while not Path('started').exists() and time.monotonic() < deadline: time.sleep(0.01)\n"
            "assert Path('started').exists()\n"
            + ("time.sleep(20)\n" if parent_stays_alive else "")
        )

    def assert_detached_gone(self, metadata):
        self.assertTrue((self.root / "started").is_file())
        self.assertEqual(metadata.quality, "guaranteed-tree")
        self.assertEqual(metadata.descendants_remaining, 0)
        time.sleep(1.5)
        self.assertFalse((self.root / "escaped").exists())

    def test_exit_kills_detached_child_without_environment_token(self):
        result = self.supervise(self.detached(False))
        self.assertEqual(result.returncode, 0)
        self.assert_detached_gone(result.supervision)

    def test_timeout_kills_detached_child_without_environment_token(self):
        with self.assertRaises(subprocess.TimeoutExpired) as caught:
            self.supervise(self.detached(True), timeout=1)
        self.assert_detached_gone(caught.exception.supervision)

    def test_unavailable_namespace_never_starts_project(self):
        with patch("verification_linux_pid_namespace._UNSHARE", Path("/usr/bin/false")):
            with self.assertRaisesRegex(ProcessSupervisionError, "NAMESPACE_UNPROVEN"):
                self.supervise("from pathlib import Path; Path('escaped').touch()")
        self.assertFalse((self.root / "escaped").exists())
