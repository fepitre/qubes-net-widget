#!/usr/bin/python3 -I
"""
Argument validation of the network services
"""

import importlib.util
import json
import unittest
from pathlib import Path

SVC = Path(__file__).resolve().parent.parent / "src/qubes-netsvc.py"
spec = importlib.util.spec_from_file_location("netsvc", SVC)
netsvc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netsvc)

UUID = "bff72a1d-9665-32b8-80ee-7df9b460fba1"
INJECT = ["--", "-a", ";", "$(id)", "a\nb", "a\0b", "`id`", "a b", "*"]
CONTROL = ["a\nb", "a\0b", "a\rb", "a\tb", "a\u202eb", "\ud800"]


def doc(obj):
    return json.dumps(obj).encode()


class Base(unittest.TestCase):
    def ok(self, verb, obj):
        return netsvc.validate(verb, netsvc.parse(doc(obj)))

    def bad(self, verb, obj, field=None):
        with self.assertRaises(netsvc.Invalid) as cm:
            netsvc.validate(verb, netsvc.parse(doc(obj)))
        if field is not None:
            self.assertEqual(cm.exception.field, field)
        return cm.exception


class Document(Base):
    def bad_raw(self, data):
        with self.assertRaises(netsvc.Invalid) as cm:
            netsvc.parse(data)
        self.assertEqual(cm.exception.field, "document")

    def test_empty_status(self):
        self.assertEqual(self.ok("status", {}), {})

    def test_not_json(self):
        for data in (b"", b"{", b"null", b"[]", b'"x"', b"1", b"\xff{}"):
            self.bad_raw(data)

    def test_duplicate_key(self):
        self.bad_raw(b'{"enabled": true, "enabled": false}')

    def test_constants(self):
        for c in (b"NaN", b"Infinity", b"-Infinity"):
            self.bad_raw(b'{"x": ' + c + b"}")

    def test_oversize(self):
        self.bad_raw(b'{"x": "' + b"a" * netsvc.MAX_INPUT + b'"}')

    def test_deep(self):
        self.bad_raw(b"[" * 40000 + b"]" * 40000)

    def test_unknown_key(self):
        for verb in netsvc.VERBS:
            self.bad(verb, {"zz": 1}, "document")

    def test_error_never_quotes_value(self):
        marker = "Marker-7f3a9c"
        for verb, obj in (
            ("connect", {"uuid": marker}),
            ("disconnect", {"device": marker}),
            ("connect", {"uuid": UUID, "ipv4": {"method": marker}}),
            ("connect", {"wifi": {"ssid": "x", "security": marker}}),
            ("forget", {"uuid": UUID, marker: 1}),
            ("connect", {"uuid": UUID, "ipv4": {"method": "auto", marker: 1}}),
        ):
            e = self.bad(verb, obj)
            self.assertNotIn(marker, str(e))
            self.assertNotIn(marker.lower(), str(e).lower())

    def test_unknown_verb(self):
        self.bad("shell", {}, "service")


class Simple(Base):
    def test_scan(self):
        self.assertEqual(self.ok("scan", {}), {"rescan": True})
        self.assertEqual(self.ok("scan", {"rescan": False}), {"rescan": False})
        for v in (0, 1, "true", None, []):
            self.bad("scan", {"rescan": v}, "rescan")

    def test_radio(self):
        self.assertEqual(self.ok("radio", {"enabled": True}), {"enabled": True})
        self.bad("radio", {}, "enabled")
        for v in (0, 1, "on", None):
            self.bad("radio", {"enabled": v}, "enabled")

    def test_disconnect(self):
        for iface in ("ens6", "wls6", "wlp0s20f3", "enp0s31f6", "eth0"):
            self.assertEqual(
                self.ok("disconnect", {"device": iface}), {"device": iface}
            )
        for iface in INJECT + [
            "",
            "lo",
            "vif5",
            "vif0.0",
            "ENS6",
            "a" * 16,
            "6ens",
            "ens-6",
            "../x",
            5,
            None,
        ]:
            self.bad("disconnect", {"device": iface}, "device")

    def test_forget(self):
        self.assertEqual(self.ok("forget", {"uuid": UUID}), {"uuid": UUID})
        for u in INJECT + [UUID.upper(), UUID[:-1], UUID + "0", "", 1]:
            self.bad("forget", {"uuid": u}, "uuid")


class Connect(Base):
    def test_uuid_or_wifi(self):
        self.bad("connect", {}, "document")
        self.bad(
            "connect",
            {"uuid": UUID, "wifi": {"ssid": "a", "security": "open"}},
            "document",
        )
        r = self.ok("connect", {"uuid": UUID})
        self.assertEqual(r["uuid"], UUID)
        self.assertIsNone(r["ipv4"])

    def test_device(self):
        r = self.ok("connect", {"uuid": UUID, "device": "ens6"})
        self.assertEqual(r["device"], "ens6")
        for d in INJECT:
            self.bad("connect", {"uuid": UUID, "device": d}, "device")


class IP(Base):
    def ip(self, version, cfg):
        return self.ok("connect", {"uuid": UUID, f"ipv{version}": cfg})[
            f"ipv{version}"
        ]

    def bad_ip(self, version, cfg, field):
        return self.bad("connect", {"uuid": UUID, f"ipv{version}": cfg}, field)

    def test_methods(self):
        self.assertEqual(self.ip(4, {"method": "auto"})["method"], "auto")
        self.assertEqual(self.ip(6, {"method": "dhcp"})["method"], "dhcp")
        self.assertEqual(self.ip(6, {"method": "auto"})["method"], "auto")
        for m in ("dhcp", "link-local", "shared", "ignore", "", None, 4):
            self.bad_ip(4, {"method": m}, "ipv4.method")
        self.bad_ip(4, {}, "ipv4.method")

    def test_manual4(self):
        r = self.ip(
            4,
            {
                "method": "manual",
                "addresses": ["192.168.10.5/24", "172.16.0.9/12"],
                "gateway": "192.168.10.1",
                "dns": ["9.9.9.9", "192.168.10.1"],
                "search": ["corp.example", "lan"],
            },
        )
        self.assertEqual([str(a) for a in r["addresses"]][0], "192.168.10.5/24")
        self.assertEqual(str(r["gateway"]), "192.168.10.1")
        self.assertEqual(r["search"], ["corp.example", "lan"])

    def test_manual4_needs_address(self):
        self.bad_ip(4, {"method": "manual"}, "ipv4.addresses")
        self.bad_ip(4, {"method": "manual", "addresses": []}, "ipv4.addresses")

    def test_addresses4(self):
        good = ["10.15.6.20/16", "192.168.1.2/31", "203.0.113.7/32"]
        for a in good:
            self.ip(4, {"method": "manual", "addresses": [a]})
        bad = INJECT + [
            "192.168.1.2",
            "192.168.1.0/24",
            "192.168.1.255/24",
            "192.168.1.2/0",
            "192.168.1.2/33",
            "192.168.1.2/024",
            "192.168.1.2/24/1",
            "010.1.1.1/8",
            "0.0.0.0/8",
            "127.0.0.1/8",
            "224.0.0.5/4",
            "240.1.1.1/4",
            "255.255.255.255/32",
            "169.254.3.3/16",
            "10.137.0.4/16",
            "10.138.1.1/24",
            "10.139.1.1/24",
            "fe80::1/64",
            "2001:db8::1/64",
            " 192.168.1.2/24",
            "192.168.1.2/24 ",
            "1.2.3.4/24\n",
            "x" * 100,
            7,
        ]
        for a in bad:
            self.bad_ip(
                4,
                {"method": "manual", "addresses": [a]},
                "ipv4.addresses[0]",
            )

    def test_addresses_count(self):
        many = [f"192.168.1.{i}/24" for i in range(1, 6)]
        self.bad_ip(
            4, {"method": "manual", "addresses": many}, "ipv4.addresses"
        )
        self.bad_ip(
            4,
            {"method": "manual", "addresses": ["192.168.1.2/24"] * 2},
            "ipv4.addresses[1]",
        )
        self.bad_ip(
            4,
            {"method": "manual", "addresses": "192.168.1.2/24"},
            "ipv4.addresses",
        )

    def test_gateway4(self):
        base = {"method": "manual", "addresses": ["192.168.1.2/24"]}
        for gw in INJECT + [
            "192.168.2.1",
            "192.168.1.2",
            "192.168.1.0",
            "192.168.1.255",
            "192.168.1.1/24",
            "10.137.0.1",
            "",
        ]:
            self.bad_ip(4, dict(base, gateway=gw), "ipv4.gateway")
        self.bad_ip(4, {"method": "auto", "gateway": "1.1.1.1"}, "ipv4.gateway")

    def test_auto_with_dns(self):
        r = self.ip(
            4, {"method": "auto", "dns": ["1.1.1.1"], "search": ["a.b"]}
        )
        self.assertEqual([str(d) for d in r["dns"]], ["1.1.1.1"])
        self.bad_ip(
            4, {"method": "auto", "addresses": ["1.2.3.4/24"]}, "ipv4.addresses"
        )
        self.bad_ip(4, {"method": "disabled", "dns": ["1.1.1.1"]}, "ipv4.dns")

    def test_dns(self):
        for d in INJECT + [
            "10.139.1.1",
            "127.0.0.53",
            "0.0.0.0",
            "::1",
            "1.1.1.1/32",
            "fe80::1",
        ]:
            self.bad_ip(4, {"method": "auto", "dns": [d]}, "ipv4.dns[0]")
        self.bad_ip(
            4, {"method": "auto", "dns": ["1.1.1.1"] * 2}, "ipv4.dns[1]"
        )
        self.bad_ip(
            4,
            {
                "method": "auto",
                "dns": ["1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.8.8"],
            },
            "ipv4.dns",
        )

    def test_search(self):
        for name in ("lan", "corp.example", "a-b.c0", "x" * 63 + ".com"):
            self.ip(4, {"method": "auto", "search": [name]})
        for name in INJECT + [
            "",
            "Corp.Example",
            "-a.com",
            "a-.com",
            "a..com",
            "a.com.",
            ".a.com",
            "a_b.com",
            "x" * 64 + ".com",
            ".".join(["abcdefgh"] * 30),
            "caf\u00e9.fr",
        ]:
            self.bad_ip(
                4, {"method": "auto", "search": [name]}, "ipv4.search[0]"
            )
        self.bad_ip(
            4,
            {"method": "auto", "search": [f"d{i}" for i in range(7)]},
            "ipv4.search",
        )

    def test_manual6(self):
        r = self.ip(
            6,
            {
                "method": "manual",
                "addresses": ["2001:DB8::5/64"],
                "gateway": "fe80::1",
                "dns": ["2606:4700:4700::1111"],
            },
        )
        self.assertEqual(str(r["addresses"][0]), "2001:db8::5/64")
        self.assertEqual(str(r["gateway"]), "fe80::1")
        r = self.ip(
            6,
            {
                "method": "manual",
                "addresses": ["2001:db8::5/64"],
                "gateway": "2001:db8::1",
            },
        )
        self.assertEqual(str(r["gateway"]), "2001:db8::1")

    def test_addresses6(self):
        for a in INJECT + [
            "2001:db8::5",
            "2001:db8::5/129",
            "2001:db8::5/0",
            "fe80::5/64",
            "fd09:24ef:4179::5/64",
            "::1/128",
            "::/0",
            "ff02::1/64",
            "::ffff:192.168.1.1/120",
            "fec0::1/64",
            "fe80::1%ens6/64",
            "192.168.1.2/24",
            "2001:db8::5/64%x",
        ]:
            self.bad_ip(
                6,
                {"method": "manual", "addresses": [a]},
                "ipv6.addresses[0]",
            )

    def test_gateway6(self):
        base = {"method": "manual", "addresses": ["2001:db8::5/64"]}
        for gw in INJECT + ["2001:db9::1", "fe80::1%ens6", "ff02::2", "::"]:
            self.bad_ip(6, dict(base, gateway=gw), "ipv6.gateway")


class Wifi(Base):
    def wifi(self, w):
        return self.ok("connect", {"wifi": w})["wifi"]

    def bad_wifi(self, w, field):
        return self.bad("connect", {"wifi": w}, field)

    def test_psk(self):
        for psk in ("12345678", "p" * 63, "a b;c$(id)`x`'\"", "F" * 64):
            r = self.wifi({"ssid": "home", "security": "wpa2-psk", "psk": psk})
            self.assertEqual(r["psk"], psk)
            self.assertEqual(r["ssid"], b"home")
        for psk in (
            ["1234567", "p" * 64, "p" * 65, "g" * 64, "caf\u00e9xxxx"]
            + ["abcdefgh" + c for c in CONTROL]
            + [12345678, None]
        ):
            self.bad_wifi(
                {"ssid": "home", "security": "wpa2-psk", "psk": psk}, "wifi.psk"
            )

    def test_sae(self):
        r = self.wifi({"ssid": "home", "security": "wpa3-psk", "psk": "x" * 8})
        self.assertEqual(r["security"], "wpa3-psk")
        self.bad_wifi(
            {"ssid": "home", "security": "wpa3-psk", "psk": "a" * 64},
            "wifi.psk",
        )

    def test_security(self):
        for sec in (
            "wep",
            "wpa-psk",
            "owe",
            "wpa2-eap",
            "wpa3-eap",
            "wpa3-eap-192",
            "",
            None,
            "WPA2-PSK",
        ):
            self.bad_wifi({"ssid": "a", "security": sec}, "wifi.security")
        self.bad_wifi({"ssid": "a"}, "wifi.security")

    def test_open(self):
        r = self.wifi({"ssid": "cafe", "security": "open", "accept_open": True})
        self.assertEqual(r["security"], "open")
        self.bad_wifi({"ssid": "cafe", "security": "open"}, "wifi.accept_open")
        self.bad_wifi(
            {"ssid": "cafe", "security": "open", "accept_open": False},
            "wifi.accept_open",
        )
        self.bad_wifi(
            {"ssid": "cafe", "security": "open", "accept_open": 1},
            "wifi.accept_open",
        )
        self.bad_wifi(
            {
                "ssid": "cafe",
                "security": "open",
                "accept_open": True,
                "psk": "12345678",
            },
            "wifi.psk",
        )

    def test_secret_fields_exclusive(self):
        self.bad_wifi({"ssid": "a", "security": "wpa2-psk"}, "wifi.psk")
        self.bad_wifi(
            {"ssid": "a", "security": "wpa2-psk", "psk": "12345678", "eap": {}},
            "wifi",
        )
        self.bad_wifi(
            {
                "ssid": "a",
                "security": "wpa2-psk",
                "psk": "12345678",
                "accept_open": True,
            },
            "wifi.accept_open",
        )

    def test_ssid(self):
        r = self.wifi(
            {"ssid_hex": "00ff41", "security": "open", "accept_open": True}
        )
        self.assertEqual(r["ssid"], b"\x00\xffA")
        r = self.wifi(
            {
                "ssid": "Caf\u00e9 -- $(x)",
                "security": "open",
                "accept_open": True,
            }
        )
        self.assertEqual(r["ssid"], "Caf\u00e9 -- $(x)".encode())
        self.assertFalse(r["hidden"])
        r = self.wifi(
            {
                "ssid": "h",
                "hidden": True,
                "security": "open",
                "accept_open": True,
            }
        )
        self.assertTrue(r["hidden"])
        for hexed in ("", "0", "abc", "GG", "AB", "aa" * 33, 5, "0x41"):
            self.bad_wifi(
                {"ssid_hex": hexed, "security": "open", "accept_open": True},
                "wifi.ssid_hex",
            )
        for text in CONTROL + ["", "x" * 33, "\u00e9" * 17]:
            self.bad_wifi(
                {"ssid": text, "security": "open", "accept_open": True},
                "wifi.ssid",
            )
        self.bad_wifi(
            {
                "ssid": "a",
                "ssid_hex": "61",
                "security": "open",
                "accept_open": True,
            },
            "wifi.ssid",
        )
        self.bad_wifi({"security": "open", "accept_open": True}, "wifi.ssid")
        self.bad_wifi(
            {
                "ssid": "a",
                "hidden": "yes",
                "security": "open",
                "accept_open": True,
            },
            "wifi.hidden",
        )


class Helpers(unittest.TestCase):
    def test_profile_name(self):
        self.assertEqual(
            netsvc.profile_name(b"My Home;$(x)", "0123abcd-0000"),
            "wifi-My-Home-x-0123abcd",
        )
        self.assertEqual(
            netsvc.profile_name(b"\xff\xfe", "0123abcd-0000"),
            "wifi-network-0123abcd",
        )

    def test_ap_security(self):
        s = netsvc.ap_security
        self.assertEqual(s(0, 0, 0), "open")
        self.assertEqual(s(1, 0, 0), "wep")
        self.assertEqual(s(1, 0, 0x100), "wpa2-psk")
        self.assertEqual(s(1, 0x100, 0), "wpa2-psk")
        self.assertEqual(s(1, 0, 0x400), "wpa3-psk")
        self.assertEqual(s(1, 0, 0x500), "wpa3-transition")
        self.assertEqual(s(1, 0, 0x200), "wpa2-eap")
        self.assertEqual(s(1, 0, 0x2200), "unsupported")
        self.assertEqual(s(0, 0, 0x800), "unsupported")


if __name__ == "__main__":
    unittest.main()
