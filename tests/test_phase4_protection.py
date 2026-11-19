import os
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

from src import database
from src.device_manager import register_device, update_device_status, get_device
from src.protection_manager import (
    get_protection_history,
    get_protection_status,
    isolate_device,
    release_device,
)
from src.network_firewall import FirewallError, FirewallResult


class FakeFirewall:
    name = "fake-test-firewall"

    def __init__(self, fail_isolate=False, fail_release=False):
        self.fail_isolate = fail_isolate
        self.fail_release = fail_release
        self.blocked = set()

    def isolate(self, ip_address):
        if self.fail_isolate:
            raise FirewallError("simulated firewall failure")
        changed = ip_address not in self.blocked
        self.blocked.add(ip_address)
        return FirewallResult(True, "isolate", ip_address, self.name, changed)

    def release(self, ip_address):
        if self.fail_release:
            raise FirewallError("simulated firewall failure")
        changed = ip_address in self.blocked
        self.blocked.discard(ip_address)
        return FirewallResult(True, "release", ip_address, self.name, changed)


class PhaseFourProtectionTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.old_db = os.environ.get("IOT_SECURITY_DB")
        self.old_enabled = os.environ.get("IOT_ENFORCEMENT_ENABLED")
        os.environ["IOT_SECURITY_DB"] = str(
            Path(self.temp_dir.name) / "phase4.db"
        )
        os.environ["IOT_ENFORCEMENT_ENABLED"] = "true"
        database.create_database()

        register_device(
            "phase4-sensor", "Phase 4 Sensor", ip_address="192.0.2.25"
        )
        update_device_status("phase4-sensor", "active")
        self.firewall = FakeFirewall()

    def tearDown(self):
        if self.old_db is None:
            os.environ.pop("IOT_SECURITY_DB", None)
        else:
            os.environ["IOT_SECURITY_DB"] = self.old_db

        if self.old_enabled is None:
            os.environ.pop("IOT_ENFORCEMENT_ENABLED", None)
        else:
            os.environ["IOT_ENFORCEMENT_ENABLED"] = self.old_enabled

        self.temp_dir.cleanup()

    def test_successful_isolation_updates_device_after_firewall(self):
        result = isolate_device("phase4-sensor", backend=self.firewall)
        self.assertEqual(result["status"], "isolated")
        self.assertIn("192.0.2.25", self.firewall.blocked)
        self.assertEqual(get_device("phase4-sensor")["status"], "isolated")
        self.assertEqual(get_protection_status()["active_isolations"], 1)

    def test_firewall_failure_never_marks_device_isolated(self):
        failing = FakeFirewall(fail_isolate=True)
        with self.assertRaises(FirewallError):
            isolate_device("phase4-sensor", backend=failing)

        self.assertEqual(get_device("phase4-sensor")["status"], "active")
        history = get_protection_history("phase4-sensor")
        self.assertEqual(history[0]["status"], "failed")

    def test_duplicate_isolation_is_idempotent(self):
        isolate_device("phase4-sensor", backend=self.firewall)
        second = isolate_device("phase4-sensor", backend=self.firewall)
        self.assertTrue(second["already_isolated"])
        self.assertEqual(len(self.firewall.blocked), 1)

    def test_release_requires_firewall_confirmation(self):
        isolate_device("phase4-sensor", backend=self.firewall)
        failing = FakeFirewall(fail_release=True)
        with self.assertRaises(FirewallError):
            release_device("phase4-sensor", backend=failing)

        self.assertEqual(get_device("phase4-sensor")["status"], "isolated")
        self.assertEqual(get_protection_status()["active_isolations"], 1)

    def test_successful_release_moves_device_to_recovering(self):
        isolate_device("phase4-sensor", backend=self.firewall)
        result = release_device("phase4-sensor", backend=self.firewall)
        self.assertEqual(result["status"], "recovering")
        self.assertNotIn("192.0.2.25", self.firewall.blocked)
        self.assertEqual(get_device("phase4-sensor")["status"], "recovering")
        self.assertEqual(get_protection_status()["active_isolations"], 0)

    def test_releasing_one_shared_ip_keeps_firewall_blocked(self):
        register_device(
            "phase4-shared", "Shared IP Sensor", ip_address="192.0.2.25"
        )
        update_device_status("phase4-shared", "active")
        isolate_device("phase4-sensor", backend=self.firewall)
        isolate_device("phase4-shared", backend=self.firewall)

        released = release_device("phase4-sensor", backend=self.firewall)

        self.assertIn("192.0.2.25", self.firewall.blocked)
        history = get_protection_history("phase4-sensor")
        self.assertTrue(history[0]["details"]["shared_address_retained"])
        self.assertEqual(released["status"], "recovering")

    def test_active_protection_prevents_ordinary_reactivation(self):
        isolate_device("phase4-sensor", backend=self.firewall)
        with self.assertRaisesRegex(ValueError, "protection is active"):
            update_device_status("phase4-sensor", "active")
        self.assertEqual(get_device("phase4-sensor")["status"], "isolated")

    def test_concurrent_isolation_requests_are_serialized(self):
        call_lock = threading.Lock()
        calls = []
        original = self.firewall.isolate

        def counted(address):
            with call_lock:
                calls.append(address)
            return original(address)

        self.firewall.isolate = counted
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(
                lambda _: isolate_device("phase4-sensor", backend=self.firewall),
                range(2),
            ))
        self.assertEqual(len(calls), 1)
        self.assertEqual(sum(bool(item["already_isolated"]) for item in results), 1)

    def test_failed_compensation_result_is_not_reported_as_success(self):
        class RejectingReleaseFirewall(FakeFirewall):
            def release(self, ip_address):
                return FirewallResult(
                    False, "release", ip_address, self.name, changed=False
                )

        with patch(
            "src.protection_manager._record_action",
            side_effect=[None, RuntimeError("database write failed")],
        ):
            with patch(
                "src.protection_manager.log_event",
                side_effect=RuntimeError("event write failed"),
            ):
                with self.assertRaisesRegex(FirewallError, "compensation"):
                    isolate_device(
                        "phase4-sensor", backend=RejectingReleaseFirewall()
                    )

        self.assertEqual(get_device("phase4-sensor")["status"], "active")

    def test_enforcement_is_disabled_by_default(self):
        os.environ["IOT_ENFORCEMENT_ENABLED"] = "false"
        with self.assertRaises(PermissionError):
            isolate_device("phase4-sensor", backend=self.firewall)
        self.assertEqual(get_device("phase4-sensor")["status"], "active")

    def test_trusted_device_cannot_be_isolated(self):
        with database.get_connection() as conn:
            conn.execute(
                "UPDATE devices SET trusted=1 WHERE device_uid=?",
                ("phase4-sensor",),
            )
        with self.assertRaises(PermissionError):
            isolate_device("phase4-sensor", backend=self.firewall)
        self.assertEqual(get_device("phase4-sensor")["status"], "active")

    def test_missing_ip_is_rejected_before_firewall(self):
        with database.get_connection() as conn:
            conn.execute(
                "UPDATE devices SET ip_address=NULL WHERE device_uid=?",
                ("phase4-sensor",),
            )
        with self.assertRaises(ValueError):
            isolate_device("phase4-sensor", backend=self.firewall)
        self.assertEqual(self.firewall.blocked, set())


if __name__ == "__main__":
    unittest.main()
