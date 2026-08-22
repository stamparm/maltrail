# coding: utf-8
"""`server.py --doctor` checks: each finding must fire on the misconfiguration it names.

The doctor exists because these failures otherwise surface as a silently half-working server
(LOG_DIR unwritable, trails months old, the reporting port taken by another process). The tests
build each failure for real - a chmod'd directory, a stale mtime, a bound socket - so the check
cannot pass vacuously.
"""

import os
import shutil
import socket
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import doctor
from core import settings


class DoctorChecks(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp(prefix="mt-doctor-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self._saved = dict(settings.config)
        self.addCleanup(self._restore)

        cfg = settings.config
        cfg.LOG_DIR = os.path.join(self.dir, "logs")
        cfg.TRAILS_FILE = os.path.join(self.dir, "trails.csv")
        cfg.UPDATE_PERIOD = 86400
        cfg.DISABLE_TRAIL_UPDATES = False
        cfg.USERS = ["admin:<sha256>:1:all"]
        cfg.USE_SSL = False
        cfg.SSL_PEM = None
        cfg.HTTP_ADDRESS = "127.0.0.1"
        cfg.HTTP_PORT = 0  # port 0 always binds, so the endpoint check stays out of the way
        cfg.UDP_ADDRESS = None
        cfg.UDP_PORT = None
        cfg.USE_SERVER_UPDATE_TRAILS = False

    def _restore(self):
        settings.config.clear()
        settings.config.update(self._saved)

    # --- log directory ---------------------------------------------------------------

    def test_missing_log_dir_fails(self):
        findings = doctor.check_log_dir()
        self.assertEqual(doctor.FAIL, findings[0][0])
        self.assertIn("does not exist", findings[0][1])

    def test_unwritable_log_dir_fails(self):
        os.makedirs(settings.config.LOG_DIR)
        if os.geteuid() == 0:
            self.skipTest("root writes anywhere")
        os.chmod(settings.config.LOG_DIR, 0o500)
        self.addCleanup(os.chmod, settings.config.LOG_DIR, 0o700)
        findings = doctor.check_log_dir()
        self.assertEqual(doctor.FAIL, findings[0][0])
        self.assertIn("not writable", findings[0][1])

    def test_healthy_log_dir_is_silent(self):
        os.makedirs(settings.config.LOG_DIR)
        self.assertEqual([], doctor.check_log_dir())

    # --- trails freshness ------------------------------------------------------------

    def test_stale_trails_warn_with_age(self):
        open(settings.config.TRAILS_FILE, "w").close()
        month_ago = time.time() - 30 * 86400
        os.utime(settings.config.TRAILS_FILE, (month_ago, month_ago))
        findings = doctor.check_trails_freshness()
        self.assertEqual(doctor.WARN, findings[0][0])
        self.assertIn("30 days", findings[0][1])

    def test_fresh_trails_are_silent(self):
        open(settings.config.TRAILS_FILE, "w").close()
        self.assertEqual([], doctor.check_trails_freshness())

    def test_missing_trails_fail(self):
        findings = doctor.check_trails_freshness()
        self.assertEqual(doctor.FAIL, findings[0][0])

    # --- users -----------------------------------------------------------------------

    def test_empty_users_fails(self):
        settings.config.USERS = []
        findings = doctor.check_users()
        self.assertEqual(doctor.FAIL, findings[0][0])

    def test_populated_users_ok(self):
        findings = doctor.check_users()
        self.assertEqual([(doctor.OK, findings[0][1])], findings)

    # --- endpoints -------------------------------------------------------------------

    def test_taken_http_port_warns(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        settings.config.HTTP_PORT = blocker.getsockname()[1]
        findings = doctor.check_http_endpoint()
        self.assertEqual(doctor.WARN, findings[0][0])
        self.assertIn("not bindable", findings[0][1])

    def test_taken_udp_intake_warns(self):
        blocker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        blocker.bind(("127.0.0.1", 0))
        self.addCleanup(blocker.close)
        settings.config.UDP_ADDRESS = "127.0.0.1"
        settings.config.UDP_PORT = blocker.getsockname()[1]
        findings = doctor.check_udp_intake()
        self.assertEqual(doctor.WARN, findings[0][0])

    def test_free_udp_intake_is_silent(self):
        settings.config.UDP_ADDRESS = "127.0.0.1"
        settings.config.UDP_PORT = 0
        self.assertEqual([], doctor.check_udp_intake())

    # --- aggregate -------------------------------------------------------------------

    def test_run_exit_code_reflects_failures(self):
        os.makedirs(settings.config.LOG_DIR)
        open(settings.config.TRAILS_FILE, "w").close()
        self.assertEqual(0, doctor.run())  # healthy baseline (port 0, fresh trails)
        settings.config.USERS = []
        import io
        out = io.StringIO()
        self.assertEqual(1, doctor.run(out))
        self.assertIn("1 problem(s)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
