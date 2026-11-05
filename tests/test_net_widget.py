#!/usr/bin/python3 -I
"""
Text the network widget shows from the network qube
"""

# pylint: disable=protected-access

import importlib.util
import json
import unittest
from importlib.machinery import SourceFileLoader
from pathlib import Path

WIDGET = Path(__file__).resolve().parent.parent / "src/qubes-net-widget"
try:
    loader = SourceFileLoader("netwidget", str(WIDGET))
    widget = importlib.util.module_from_spec(
        importlib.util.spec_from_loader("netwidget", loader)
    )
    loader.exec_module(widget)
except (ImportError, ValueError):
    widget = None

UUID = "bff72a1d-9665-32b8-80ee-7df9b460fba1"
ARABIC = "\u0634\u0628\u0643\u0629"
HOSTILE = [
    ARABIC,
    "caf\u00e9",
    "a\u0301",
    "\U0001f600",
    "a\u202eb",
    "a\nb",
    "a\x7fb",
    "\u00a0",
    "\ufeff",
]


def printable_ascii(text):
    return all(0x20 <= ord(c) < 0x7F for c in text)


def strings(obj):
    if isinstance(obj, dict):
        for key, value in obj.items():
            yield from strings(key)
            yield from strings(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from strings(value)
    elif isinstance(obj, str):
        yield obj
    elif isinstance(obj, bytes):
        yield widget.ssid_label(obj)


def status(name, ssid):
    ip4 = {
        "addresses": ["192.168.1.20/24"],
        "gateway": "192.168.1.1",
        "dns": ["192.168.1.1"],
    }
    ip6 = {"addresses": [], "gateway": None, "dns": ["fe80::1%wls6"]}
    return {
        "radio": {"hardware": True, "enabled": True, "devices": 1},
        "devices": [
            {
                "iface": "wls6",
                "type": "wifi",
                "state": "connected",
                "profile": UUID,
                "default4": True,
                "default6": False,
                "ipv4": ip4,
                "ipv6": ip6,
                "ap": {
                    "ssid_hex": ssid.hex(),
                    "signal": 70,
                    "security": "open",
                },
            }
        ],
        "profiles": [
            {
                "uuid": UUID,
                "type": "wifi",
                "name": name,
                "saved": True,
                "active": "wls6",
                "ipv4": dict(
                    ip4, method="manual", search=[name, "lab.example"]
                ),
                "ipv6": {"method": "auto"},
                "ssid_hex": ssid.hex(),
                "hidden": False,
                "security": "wpa2-psk",
            }
        ],
        "primary": UUID,
    }


class MockProc:
    returncode = 0


@unittest.skipIf(widget is None, "no PyGObject with GTK 3")
class Mode(unittest.TestCase):
    ascii_only = False

    def setUp(self):
        self.saved = widget.ASCII_ONLY
        widget.ASCII_ONLY = self.ascii_only

    def tearDown(self):
        widget.ASCII_ONLY = self.saved

    def error_shown(self, error):
        transport = widget.Transport("sys-net", dom0=self.ascii_only)
        answer = json.dumps({"ok": False, "error": error}).encode()
        popen = widget.subprocess.Popen
        exchange = widget.Transport._exchange
        widget.subprocess.Popen = lambda *a, **k: MockProc()
        widget.Transport._exchange = staticmethod(lambda p, d: (answer, b""))
        try:
            with self.assertRaises(widget.CallError) as cm:
                transport.call("qubes.NetStatus", {})
        finally:
            widget.subprocess.Popen = popen
            widget.Transport._exchange = staticmethod(exchange)
        return str(cm.exception)


class Dom0(Mode):
    ascii_only = True

    def test_safe_text(self):
        s = widget.safe_text
        self.assertEqual(s("Home Wi-Fi ~!"), "Home Wi-Fi ~!")
        self.assertEqual(s(ARABIC), "\\u0634\\u0628\\u0643\\u0629")
        self.assertEqual(s("caf\u00e9"), "caf\\xe9")
        self.assertEqual(s("\U0001f600"), "\\U0001f600")
        self.assertEqual(s("a\nb\x7f"), "a\\x0ab\\x7f")
        self.assertEqual(s("abcdef", 3), "abc...")
        for text in HOSTILE:
            self.assertTrue(printable_ascii(s(text)), text)

    def test_ssid_label(self):
        label = widget.ssid_label
        self.assertEqual(label(b"net-wpa2"), "net-wpa2")
        self.assertEqual(
            label(f"net-{ARABIC}".encode()), "net-\\u0634\\u0628\\u0643\\u0629"
        )
        # Invalid bytes and backslashes stay distinct
        self.assertEqual(label("caf\u00e9".encode()), "caf\\xe9")
        self.assertEqual(label(b"caf\xe9"), "caf\\udce9")
        self.assertEqual(label(b"caf\\xe9"), "caf\\\\xe9")
        for text in HOSTILE:
            self.assertTrue(printable_ascii(label(text.encode())), text)

    def test_status(self):
        for text in HOSTILE:
            ssid = f"x{text}".encode()[:32]
            out = widget.clean_status(status(f"x{text}", ssid))
            for shown in strings(out):
                self.assertTrue(printable_ascii(shown), repr(shown))

    def test_scan(self):
        networks = [
            {
                "ssid_hex": text.encode().hex(),
                "signal": 40,
                "security": "wpa2-psk",
                "saved": None,
                "active": False,
            }
            for text in HOSTILE
        ]
        radio = {"hardware": True, "enabled": True, "devices": 1}
        out = widget.clean_scan({"radio": radio, "networks": networks})
        for shown in strings(out):
            self.assertTrue(printable_ascii(shown), repr(shown))

    def test_error(self):
        for text in HOSTILE:
            shown = self.error_shown(f"Failed to connect {text}")
            self.assertTrue(printable_ascii(shown), repr(shown))
        self.assertEqual(
            self.error_shown(f"No {ARABIC}"),
            "From sys-net: No \\u0634\\u0628\\u0643\\u0629",
        )


class GuiDomain(Mode):
    def test_safe_text(self):
        s = widget.safe_text
        for text in (ARABIC, "caf\u00e9", "a\u0301", "\U0001f600"):
            self.assertEqual(s(text), text)
        self.assertEqual(s("a\u202eb"), "a\\u202eb")
        self.assertEqual(s("a\nb"), "a\\x0ab")
        self.assertEqual(s("\ufeff\u00a0"), "\\ufeff\\xa0")

    def test_ssid_label(self):
        label = widget.ssid_label
        self.assertEqual(label(f"net-{ARABIC}".encode()), f"net-{ARABIC}")
        self.assertEqual(label(b"\xff\x00a"), "\\udcff\\x00a")
        self.assertEqual(label(b"a\\b"), "a\\\\b")

    def test_status(self):
        out = widget.clean_status(status(ARABIC, ARABIC.encode()))
        self.assertEqual(out["profiles"][0]["name"], ARABIC)
        self.assertEqual(out["profiles"][0]["ipv4"]["search"], ["lab.example"])
        self.assertEqual(widget.ssid_label(out["profiles"][0]["ssid"]), ARABIC)

    def test_error(self):
        self.assertEqual(
            self.error_shown(f"No {ARABIC}"),
            f"From the network qube: No {ARABIC}",
        )


@unittest.skipIf(widget is None, "no PyGObject with GTK 3")
class Address(unittest.TestCase):
    def test_kept(self):
        a = widget._addr
        self.assertEqual(a("192.168.1.1"), "192.168.1.1")
        self.assertEqual(a("2001:DB8::1"), "2001:db8::1")
        self.assertIn(
            a("::ffff:192.0.2.1"), ("::ffff:192.0.2.1", "::ffff:c000:201")
        )
        self.assertEqual(a("fe80::1%wls6"), "fe80::1%wls6")
        self.assertEqual(a("fe80::1%2"), "fe80::1%2")
        self.assertEqual(a("10.0.0.2/8", True), "10.0.0.2/8")
        self.assertEqual(a("fe80::1%eth0/64", True), "fe80::1%eth0/64")

    def test_scope(self):
        for scope in HOSTILE + ["a b", "a/b", "ETH0", "a" * 16, "a;b"]:
            for value, prefix in (
                (f"fe80::1%{scope}", False),
                (f"fe80::1%{scope}/64", True),
            ):
                with self.assertRaises(widget.BadAnswer, msg=repr(value)):
                    widget._addr(value, prefix)

    def test_not_address(self):
        for value in ("", "1.2.3", "1.2.3.4/33", "\u0661.2.3.4", 4, None):
            with self.assertRaises(widget.BadAnswer, msg=repr(value)):
                widget._addr(value)


if __name__ == "__main__":
    unittest.main()
