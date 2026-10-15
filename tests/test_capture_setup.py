"""Startup capture discovery overrides stale selection without changing secrets."""
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dotenv import dotenv_values
from launcher.capture_setup import prepare_host_capture


class CaptureSetupTests(unittest.TestCase):
    def test_refresh_preserves_other_settings_and_uses_stable_devices(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            original = b'# keep comment\r\nWIFI_PASSWORD="fixture only"\r\nHOST_CAPTURE_INTERFACES="99"\r\nMQTT_PORT=1883\r\n'
            path.write_bytes(original)
            selected = [r"\Device\NPF_{00112233-4455-6677-8899-aabbccddeeff}"]
            with patch("launcher.capture_setup.find_tshark_path", return_value="tshark"), \
                 patch("launcher.capture_setup.get_available_interfaces", return_value=[]), \
                 patch("launcher.capture_setup.select_best_interfaces", return_value=selected) as selecting, \
                 patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "old-card"}):
                self.assertEqual(prepare_host_capture(directory), selected)
                selecting.assert_called_once_with([], configured_value="auto")
                self.assertEqual(os.environ["HOST_CAPTURE_INTERFACES"], selected[0])
                content = path.read_bytes()
                self.assertIn(b'WIFI_PASSWORD="fixture only"\r\n', content)
                self.assertIn(b'MQTT_PORT=1883\r\n', content)
                self.assertEqual(dotenv_values(path)["HOST_CAPTURE_INTERFACES"], selected[0])
                mtime = path.stat().st_mtime_ns
                prepare_host_capture(directory)
                self.assertEqual(path.stat().st_mtime_ns, mtime)

    def test_discovery_failure_keeps_previous_env_and_runtime_selection(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            original = b'HOST_CAPTURE_INTERFACES="old"\nOTHER=unchanged\n'
            path.write_bytes(original)
            with patch("launcher.capture_setup.find_tshark_path", return_value="tshark"), \
                 patch("launcher.capture_setup.get_available_interfaces", side_effect=ValueError("no adapters")), \
                 patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "old"}):
                with self.assertRaises(ValueError):
                    prepare_host_capture(directory)
                self.assertEqual(path.read_bytes(), original)
                self.assertEqual(os.environ["HOST_CAPTURE_INTERFACES"], "old")

    def test_creates_missing_capture_setting(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".env"
            path.write_bytes(b"OTHER=unchanged")
            with patch("launcher.capture_setup.find_tshark_path", return_value="tshark"), \
                 patch("launcher.capture_setup.get_available_interfaces", return_value=[]), \
                 patch("launcher.capture_setup.select_best_interfaces", return_value=["eth0"]), \
                 patch.dict(os.environ):
                prepare_host_capture(directory)
            self.assertEqual(path.read_bytes(), b'OTHER=unchanged\nHOST_CAPTURE_INTERFACES="eth0"\n')
