import struct
import unittest

from travelsec import bluetooth, dnsclient, dnslog, oui
from travelsec.common import split_nmcli

INFO = """Device AC:DE:48:00:11:22 (public)
\tName: Some Mac
\tAlias: Some Mac
\tPaired: no
\tRSSI: 0xffffffc1 (-63)
\tUUID: Unknown                   (0000feed-0000-1000-8000-00805f9b34fb)
\tManufacturerData.Key: 0x0075 (117)
\tManufacturerData.Value:
  00 09 01 00 00 00 06 01 00 00 00 00 00 00 00 00  ................
  00 00 00 00                                      ....
\tServiceData.0000fcf1-0000-1000-8000-00805f9b34fb:
  04 ab e6 18                                      ....
\tAdvertisingFlags:
  02                                               .
"""

STREAM = """Discovery started
[CHG] Device AC:DE:48:00:11:22 RSSI: 0xffffffc1 (-63)
[CHG] Device AC:DE:48:00:11:22 ManufacturerData.Key: 0x004c (76)
[CHG] Device AC:DE:48:00:11:22 ManufacturerData.Value:
  12 19 10 aa bb cc dd ee ff 00 11 22 33 44 55 66  ................
  77                                               .
[CHG] Device AC:DE:48:00:11:22 RSSI: 0xffffffb0 (-80)
[NEW] Device 11:22:33:44:55:66 Thing
"""


class BluetoothTests(unittest.TestCase):
    def test_parse_info(self):
        d = bluetooth.parse_info(INFO)
        self.assertEqual(d["mac"], "AC:DE:48:00:11:22")
        self.assertEqual(d["addr_type"], "public")
        self.assertEqual(d["rssi"], -63)
        self.assertEqual(d["manufacturer"]["0x0075"][:8], "00090100")
        self.assertEqual(len(d["manufacturer"]["0x0075"]), 40)
        self.assertEqual(d["service_data"]["0000fcf1-0000-1000-8000-00805f9b34fb"], "04abe618")
        self.assertIn("0000feed-0000-1000-8000-00805f9b34fb", d["uuids"])

    def test_scan_stream_keeps_strongest_rssi(self):
        devs = bluetooth.parse_scan_stream(STREAM)
        d = devs["AC:DE:48:00:11:22"]
        self.assertEqual(d["rssi"], -63)
        self.assertTrue(d["manufacturer"]["0x004c"].startswith("1219"))
        self.assertNotIn("rssi", devs["11:22:33:44:55:66"])

    def test_classify(self):
        airtag = {"manufacturer": {"0x004c": "1219" + "00" * 25}}
        self.assertEqual(bluetooth.classify(airtag)[:2], ("findmy-separated", "high"))
        near_owner = {"manufacturer": {"0x004c": "1202" + "00" * 2}}
        self.assertEqual(bluetooth.classify(near_owner)[1], "info")
        tile = {"uuids": ["0000feed-0000-1000-8000-00805f9b34fb"]}
        self.assertEqual(bluetooth.classify(tile)[0], "tracker")
        cam = {"name": "IPC_A1", "rssi": -50}
        self.assertEqual(bluetooth.classify(cam)[:2], ("camera-like", "high"))
        self.assertIsNone(bluetooth.classify({"name": "Galaxy Buds"})[0])


class DnsTests(unittest.TestCase):
    def test_roundtrip_with_compression(self):
        q = dnsclient.build_query("example.com", "A", qid=0x1234)
        # Response: header + question + answer using a compression pointer to offset 12
        hdr = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 2, 0, 0)
        question = q[12:]
        a = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + bytes([93, 184, 216, 34])
        txt = b"\xc0\x0c" + struct.pack(">HHIH", 16, 1, 60, 4) + b"\x03SEA"
        ans = dnsclient.parse_response(hdr + question + a + txt)
        self.assertEqual(ans.rcode, "NOERROR")
        self.assertEqual(ans.values("A"), ["93.184.216.34"])
        self.assertEqual(ans.values("TXT"), ["SEA"])

    def test_nxdomain(self):
        q = dnsclient.build_query("nope.example", qid=1)
        hdr = struct.pack(">HHHHHH", 1, 0x8183, 1, 0, 0, 0)
        self.assertEqual(dnsclient.parse_response(hdr + q[12:]).rcode, "NXDOMAIN")


class MiscTests(unittest.TestCase):
    def test_split_nmcli(self):
        self.assertEqual(split_nmcli(r"yes:Café\:Guest:AA\:BB\:CC\:DD\:EE\:FF:WPA2"),
                         ["yes", "Café:Guest", "AA:BB:CC:DD:EE:FF", "WPA2"])

    def test_randomized_mac(self):
        self.assertTrue(oui.is_randomized("3E:00:00:12:34:56"))
        self.assertFalse(oui.is_randomized("AC:DE:48:00:11:22"))
        self.assertIsNone(oui.vendor("3E:00:00:12:34:56"))

    def test_category(self):
        self.assertEqual(oui.category("Hangzhou Hikvision Digital Technology Co.,Ltd."), "camera")
        self.assertEqual(oui.category("Espressif Inc."), "iot-module")
        self.assertIsNone(oui.category("Intel Corporate"))

    def test_dnslog_suffix_match(self):
        self.assertEqual(dnslog.classify("acr0.samsungacr.com", dnslog.KNOWN, set()), "tv-acr")
        self.assertIsNone(dnslog.classify("notsamsungacr.com", dnslog.KNOWN, set()))
        self.assertEqual(dnslog.classify("ads.example.net", {}, {"ads.example.net"}), "blocklist")


if __name__ == "__main__":
    unittest.main()
