
import unittest
from unittest.mock import patch

import app as app_module


class DashboardProtectionStatusTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()

    def protection(self, enabled):
        return {
            "enabled": enabled,
            "active_isolations": 7,
            "total_actions": 12,
            "protections": [],
        }

    def test_dashboard_uses_actual_isolation_count_when_disabled(self):
        with patch.object(
            app_module, "get_protection_status",
            return_value=self.protection(False),
        ), patch.object(app_module.shutil, "which", return_value=None):
            data = app_module.get_dashboard_data()

        self.assertEqual(data["isolations"], 7)
        self.assertEqual(data["security_status"], "Protection disabled")

    def test_dashboard_reports_monitoring_only_without_nft(self):
        with patch.object(
            app_module, "get_protection_status",
            return_value=self.protection(True),
        ), patch.object(app_module.shutil, "which", return_value=None):
            data = app_module.get_dashboard_data()

        self.assertEqual(data["isolations"], 7)
        self.assertEqual(data["security_status"], "Monitoring only")

    def test_dashboard_reports_configured_protection_with_nft(self):
        with patch.object(
            app_module, "get_protection_status",
            return_value=self.protection(True),
        ), patch.object(app_module.shutil, "which", return_value="/usr/sbin/nft"):
            data = app_module.get_dashboard_data()

        self.assertEqual(data["isolations"], 7)
        self.assertEqual(
            data["security_status"],
            "Configured — live enforcement unverified",
        )
        self.assertIn("still require", data["security_status_detail"])


if __name__ == "__main__":
    unittest.main()
