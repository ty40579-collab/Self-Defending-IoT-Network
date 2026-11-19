import os
import unittest
from unittest.mock import patch

import app as app_module


class ProtectionApiTests(unittest.TestCase):
    def setUp(self):
        self.client = app_module.app.test_client()
        self.env = patch.dict(
            os.environ,
            {
                "IOT_ENFORCEMENT_API_TOKEN": "test-secret-token",
                "IOT_ENFORCEMENT_ENABLED": "true",
            },
        )
        self.env.start()
        self.headers = {"Authorization": "Bearer test-secret-token"}

    def tearDown(self):
        self.env.stop()

    def test_api_returns_503_when_token_is_not_configured(self):
        with patch.dict(os.environ, {"IOT_ENFORCEMENT_API_TOKEN": ""}):
            response = self.client.get("/api/protection/status")
        self.assertEqual(response.status_code, 503)

    def test_api_rejects_missing_bearer_token(self):
        response = self.client.get("/api/protection/status")
        self.assertEqual(response.status_code, 401)

    def test_api_rejects_invalid_bearer_token(self):
        response = self.client.get(
            "/api/protection/status",
            headers={"Authorization": "Bearer wrong-token"},
        )
        self.assertEqual(response.status_code, 401)

    def test_valid_token_reads_protection_status(self):
        expected = {
            "enabled": True,
            "active_isolations": 2,
            "total_actions": 4,
            "protections": [],
        }
        with patch.object(
            app_module, "get_protection_status", return_value=expected
        ):
            response = self.client.get(
                "/api/protection/status", headers=self.headers
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)

    def test_valid_token_reads_device_history(self):
        history = [{"action": "isolate", "status": "success"}]
        with patch.object(
            app_module, "get_protection_history", return_value=history
        ) as history_mock:
            response = self.client.get(
                "/api/protection/devices/sensor-1/history?limit=20",
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["history"], history)
        history_mock.assert_called_once_with("sensor-1", limit=20)

    def test_valid_token_calls_isolation_manager(self):
        result = {
            "device_uid": "sensor-1",
            "status": "isolated",
            "ip_address": "192.0.2.10",
        }
        with patch.object(
            app_module, "isolate_device", return_value=result
        ) as isolate_mock:
            response = self.client.post(
                "/api/protection/devices/sensor-1/isolate",
                headers=self.headers,
                json={"reason": "Confirmed critical threat"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], result)
        isolate_mock.assert_called_once_with(
            "sensor-1", reason="Confirmed critical threat"
        )

    def test_valid_token_calls_release_manager(self):
        result = {"device_uid": "sensor-1", "status": "recovering"}
        with patch.object(
            app_module, "release_device", return_value=result
        ) as release_mock:
            response = self.client.post(
                "/api/protection/devices/sensor-1/release",
                headers=self.headers,
                json={"reason": "Manual recovery"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["result"], result)
        release_mock.assert_called_once_with(
            "sensor-1", reason="Manual recovery"
        )

    def test_enforcement_disabled_is_reported_as_forbidden(self):
        with patch.object(
            app_module,
            "isolate_device",
            side_effect=PermissionError("Network enforcement is disabled"),
        ):
            response = self.client.post(
                "/api/protection/devices/sensor-1/isolate",
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 403)

    def test_firewall_failure_is_reported_as_bad_gateway(self):
        from src.network_firewall import FirewallError

        with patch.object(
            app_module,
            "isolate_device",
            side_effect=FirewallError("Firewall did not confirm isolation"),
        ):
            response = self.client.post(
                "/api/protection/devices/sensor-1/isolate",
                headers=self.headers,
            )

        self.assertEqual(response.status_code, 502)

    def test_unknown_request_fields_are_rejected(self):
        with patch.object(app_module, "isolate_device") as isolate_mock:
            response = self.client.post(
                "/api/protection/devices/sensor-1/isolate",
                headers=self.headers,
                json={"reason": "test", "force": True},
            )

        self.assertEqual(response.status_code, 400)
        isolate_mock.assert_not_called()

    def test_invalid_history_limit_is_rejected(self):
        response = self.client.get(
            "/api/protection/devices/sensor-1/history?limit=not-a-number",
            headers=self.headers,
        )
        self.assertEqual(response.status_code, 400)

    def test_status_patch_cannot_fake_isolation_or_recovery(self):
        for status in ("isolated", "recovering"):
            with self.subTest(status=status):
                with patch.object(
                    app_module, "update_device_status"
                ) as update_mock:
                    response = self.client.patch(
                        "/api/devices/sensor-1/status",
                        json={"status": status},
                    )

                self.assertEqual(response.status_code, 409)
                update_mock.assert_not_called()

    def test_status_patch_rejects_non_string_status(self):
        invalid_values = [[], {}, 123]
        for value in invalid_values:
            with self.subTest(value=value):
                with patch.object(
                    app_module, "update_device_status"
                ) as update_mock:
                    response = self.client.patch(
                        "/api/devices/sensor-1/status",
                        json={"status": value},
                    )

                self.assertEqual(response.status_code, 400)
                update_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
