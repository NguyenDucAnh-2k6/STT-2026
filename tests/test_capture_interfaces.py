"""Adapter discovery keeps lab scope explicit and survives changing NIC indices."""
import os
import unittest
from unittest.mock import patch, MagicMock

from firmware.host_probe.tshark_engine import select_best_interfaces
from firmware.host_probe.interface_discovery import active_adapter_ids


class CaptureInterfaceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.interfaces = [
            {"index": "1", "device": "virtual", "name": "vEthernet (WSL)"},
            {"index": "2", "device": "wifi-device", "name": "Wi-Fi"},
            {"index": "5", "device": "eth-device", "name": "Ethernet 2"},
            {"index": "9", "device": "loop-device", "name": "Loopback"}]

    def test_auto_skips_disconnected_wifi_virtual_and_loopback(self) -> None:
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "auto"}), \
             patch("firmware.host_probe.tshark_engine.active_adapter_ids", return_value={"ethernet 2", "vethernet (wsl)"}):
            self.assertEqual(select_best_interfaces(self.interfaces), ["eth-device"])

    def test_empty_auto_selects_both_active_physical_adapters(self) -> None:
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": ""}), \
             patch("firmware.host_probe.tshark_engine.active_adapter_ids", return_value={"wi-fi", "ethernet 2"}):
            self.assertEqual(select_best_interfaces(self.interfaces), ["wifi-device", "eth-device"])

    def test_explicit_loopback_and_friendly_names_are_stable(self) -> None:
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "9,Wi-Fi"}):
            self.assertEqual(select_best_interfaces(self.interfaces), ["loop-device", "wifi-device"])
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "missing"}):
            with self.assertRaises(ValueError):
                select_best_interfaces(self.interfaces)

    def test_no_link_does_not_silently_select_disconnected_adapter(self) -> None:
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "auto"}), \
             patch("firmware.host_probe.tshark_engine.active_adapter_ids", return_value=set()):
            with self.assertRaises(ValueError):
                select_best_interfaces(self.interfaces)

    def test_windows_guid_matches_npcap_after_index_changes(self) -> None:
        guid = "00112233-4455-6677-8899-aabbccddeeff"
        entries = [{"index": "47", "name": "localized driver name", "device": "\\Device\\NPF_{"+guid.upper()+"}"}]
        with patch.dict(os.environ, {"HOST_CAPTURE_INTERFACES": "auto"}), \
             patch("firmware.host_probe.tshark_engine.active_adapter_ids", return_value={guid}):
            self.assertEqual(select_best_interfaces(entries), [entries[0]["device"]])

    def test_os_query_includes_only_up_adapter_guids(self) -> None:
        with patch("firmware.host_probe.interface_discovery.sys.platform", "win32"), \
             patch("firmware.host_probe.interface_discovery.psutil.net_if_stats", return_value={"Wi-Fi": MagicMock(isup=True)}), \
             patch("firmware.host_probe.interface_discovery.subprocess.check_output", return_value=
                   '[{"Name":"Wi-Fi","Status":"Up","InterfaceGuid":"00112233-4455-6677-8899-aabbccddeeff"},{"Name":"Ethernet","Status":"Disconnected","InterfaceGuid":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}]'):
            active = active_adapter_ids()
            self.assertIn("00112233-4455-6677-8899-aabbccddeeff", active)
            self.assertNotIn("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", active)
