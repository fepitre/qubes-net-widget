#!/usr/bin/python3 -I
"""
Network services against a mock NetworkManager
"""

# pylint: disable=protected-access

import importlib.util
import fcntl
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

SVC = Path(__file__).resolve().parent.parent / "src/qubes-netsvc.py"
spec = importlib.util.spec_from_file_location("netsvc", SVC)
netsvc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(netsvc)

try:
    import gi

    gi.require_version("NM", "1.0")
    from gi.repository import NM, GLib
except (ImportError, ValueError):
    NM = None

WIRED = "6f1c2a8e-3b5d-4e7f-9a1b-2c3d4e5f6a7b"
HOME = "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d6e"
VPN = "3d4e5f6a-7b8c-4dae-8f1a-2b3c4d5e6f7a"
SECRET = "correct horse battery"
RSN_PSK = netsvc.SEC_PSK
RSN_SAE = netsvc.SEC_SAE
RSN_EAP = netsvc.SEC_8021X


class Result:
    def __init__(self, value=None, error=False):
        self.value = value
        self.error = error


def finished(result):
    if result.error:
        raise GLib.Error("mock failure")
    return result.value


def request(verb, obj):
    return netsvc.validate(verb, netsvc.parse(json.dumps(obj).encode()))


if NM is not None:

    class MockRemote(NM.SimpleConnection):
        """
        Saved profile of the mock NetworkManager
        """

        def __init__(self, filename=None):
            super().__init__()
            self.filename = filename
            self.deleted = 0
            self.updates = []
            self.update_flags = []
            self.keep_file = False

        def get_unsaved(self):
            return False

        def get_filename(self):
            return self.filename

        def delete_async(self, _cancellable, cb):
            self.deleted += 1
            if self.filename and not self.keep_file:
                os.unlink(self.filename)
            cb(None, Result())

        def delete_finish(self, result):
            return finished(result)

        def update2(self, settings, flags, _args, _cancellable, cb):
            self.updates.append(NM.SimpleConnection.new_from_dbus(settings))
            self.update_flags.append(flags)
            cb(None, Result())

        def update2_finish(self, result):
            return finished(result)

else:
    MockRemote = None


def profile(
    uuid, kind, name, ssid=None, mgmt=None, pmf=None, filename=None, **kw
):
    rc = MockRemote(filename)
    sc = NM.SettingConnection.new()
    sc.set_property(NM.SETTING_CONNECTION_ID, name)
    sc.set_property(NM.SETTING_CONNECTION_UUID, uuid)
    kinds = {
        "ethernet": ("802-3-ethernet", NM.SettingWired),
        "wifi": ("802-11-wireless", NM.SettingWireless),
        "vpn": ("vpn", NM.SettingVpn),
        "wireguard": ("wireguard", NM.SettingWireGuard),
    }
    ctype, setting = kinds[kind]
    sc.set_property(NM.SETTING_CONNECTION_TYPE, ctype)
    rc.add_setting(sc)
    s = setting.new()
    if kind == "wifi":
        s.set_property(NM.SETTING_WIRELESS_SSID, GLib.Bytes.new(ssid))
        s.set_property(
            NM.SETTING_WIRELESS_MODE, kw.get("mode", "infrastructure")
        )
    rc.add_setting(s)
    if "timestamp" in kw:
        sc.set_property(NM.SETTING_CONNECTION_TIMESTAMP, kw["timestamp"])
    if mgmt:
        ws = NM.SettingWirelessSecurity.new()
        ws.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, mgmt)
        if mgmt in ("wpa-psk", "sae"):
            ws.set_property(NM.SETTING_WIRELESS_SECURITY_PSK, SECRET)
        if pmf is not None:
            ws.set_property(NM.SETTING_WIRELESS_SECURITY_PMF, pmf)
        rc.add_setting(ws)
    for new, method in (
        (NM.SettingIP4Config.new, kw.get("ipv4", "auto")),
        (NM.SettingIP6Config.new, "auto"),
    ):
        ip = new()
        ip.set_property(NM.SETTING_IP_CONFIG_METHOD, method)
        rc.add_setting(ip)
    return rc


class MockAP:
    def __init__(self, ssid, strength=50, flags=0, wpa=0, rsn=0, freq=2412):
        self.ssid = ssid
        self.strength = strength
        self.flags = flags
        self.wpa = wpa
        self.rsn = rsn
        self.freq = freq

    def get_ssid(self):
        return GLib.Bytes.new(self.ssid) if self.ssid else None

    def get_strength(self):
        return self.strength

    def get_frequency(self):
        return self.freq

    def get_flags(self):
        return self.flags

    def get_wpa_flags(self):
        return self.wpa

    def get_rsn_flags(self):
        return self.rsn


class MockIPConfig:
    def __init__(self, family, addresses=(), gateway=None, dns=()):
        self.addresses = []
        for a in addresses:
            address, prefix = a.split("/")
            self.addresses.append(
                NM.IPAddress.new(family, address, int(prefix))
            )
        self.gateway = gateway
        self.dns = list(dns)

    def get_addresses(self):
        return self.addresses

    def get_gateway(self):
        return self.gateway

    def get_nameservers(self):
        return self.dns


class MockActive:
    def __init__(self, uuid, state=None, default=False, default6=False):
        self.uuid = uuid
        self.state = state
        self.default = default
        self.default6 = default6

    def get_uuid(self):
        return self.uuid

    def get_state(self):
        return self.state

    def get_default(self):
        return self.default

    def get_default6(self):
        return self.default6


class MockDevice:
    def __init__(self, iface, kind="wifi", managed=True, **kw):
        self.iface = iface
        self.kind = {
            "wifi": NM.DeviceType.WIFI,
            "ethernet": NM.DeviceType.ETHERNET,
            "wireguard": NM.DeviceType.WIREGUARD,
            "tun": NM.DeviceType.TUN,
        }[kind]
        self.managed = managed
        self.state = kw.get("state", NM.DeviceState.DISCONNECTED)
        self.active = kw.get("active")
        self.ip4 = kw.get("ip4")
        self.ip6 = kw.get("ip6")
        self.aps = list(kw.get("aps", ()))
        self.current = kw.get("current")
        self.reason = kw.get("reason", NM.DeviceStateReason.NONE)
        self.last_scan = 0
        self.scans = 0
        self.scan_error = False
        self.disconnects = 0
        self.disconnect_error = False
        self.deactivating = 0

    def get_device_type(self):
        return self.kind

    def get_iface(self):
        return self.iface

    def get_managed(self):
        return self.managed

    def get_state(self):
        if self.deactivating:
            self.deactivating -= 1
            if not self.deactivating:
                self.state = NM.DeviceState.DISCONNECTED
        return self.state

    def get_active_connection(self):
        return self.active

    def get_ip4_config(self):
        return self.ip4

    def get_ip6_config(self):
        return self.ip6

    def get_active_access_point(self):
        return self.current

    def get_access_points(self):
        return self.aps

    def get_last_scan(self):
        return self.last_scan

    def get_state_reason(self):
        return self.reason

    def request_scan_async(self, _cancellable, cb):
        self.scans += 1
        if not self.scan_error:
            self.last_scan += 1
        cb(None, Result(error=self.scan_error))

    def request_scan_finish(self, result):
        return finished(result)

    def disconnect_async(self, _cancellable, cb):
        self.disconnects += 1
        if not self.disconnect_error:
            self.active = None
            self.state = NM.DeviceState.DEACTIVATING
            self.deactivating = 3
        cb(None, Result(error=self.disconnect_error))

    def disconnect_finish(self, result):
        return finished(result)


class MockClient:
    def __init__(self, devices=(), connections=(), hardware=True, enabled=True):
        self.devices = list(devices)
        self.connections = list(connections)
        self.hardware = hardware
        self.enabled = enabled
        self.primary = None
        self.outcome = NM.ActiveConnectionState.ACTIVATED
        self.activated = []
        self.added = []
        self.properties = []

    def get_devices(self):
        return self.devices

    def get_connections(self):
        return self.connections

    def get_active_connections(self):
        return [d.active for d in self.devices if d.active is not None]

    def get_primary_connection(self):
        return self.primary

    def wireless_hardware_get_enabled(self):
        return self.hardware

    def wireless_get_enabled(self):
        return self.enabled

    def activate_connection_async(self, rc, dev, _specific, _cancel, cb):
        self.activated.append((rc, dev))
        cb(None, Result(MockActive(rc.get_uuid(), self.outcome)))

    def activate_connection_finish(self, result):
        return finished(result)

    def add_connection2(self, settings, flags, _args, _out, _cancel, cb):
        conn = NM.SimpleConnection.new_from_dbus(settings)
        self.added.append((conn, flags))
        rc = MockRemote()
        rc.replace_settings_from_connection(conn)
        self.connections.append(rc)
        cb(None, Result((rc, None)))

    def add_connection2_finish(self, result):
        return finished(result)

    def dbus_set_property(self, path, iface, name, value, *rest):
        self.properties.append((path, iface, name, value.unpack()))
        if name == "WirelessEnabled":
            self.enabled = value.unpack()
        rest[-1](None, Result())

    def dbus_set_property_finish(self, result):
        return finished(result)


@unittest.skipIf(NM is None, "no libnm")
class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.keyfiles = self.tmp / "system-connections"
        self.keyfiles.mkdir()
        self.hook_log = self.tmp / "hook.log"
        hook = self.tmp / "hook"
        hook.write_text(f'#!/bin/sh\necho "$@" >> {self.hook_log}\n')
        hook.chmod(0o755)
        for name, value in (
            ("KEYFILES", str(self.keyfiles)),
            ("HOOK", str(hook)),
        ):
            patcher = mock.patch.object(netsvc, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def network(self, client):
        n = netsvc.Network.__new__(netsvc.Network)
        n.GLib, n.NM, n.client = GLib, NM, client
        return n

    def hook_calls(self):
        if not self.hook_log.exists():
            return []
        return self.hook_log.read_text().splitlines()


class Status(Base):
    def client(self):
        wired = MockActive(WIRED, default=True)
        eth = MockDevice(
            "ens6",
            "ethernet",
            state=NM.DeviceState.ACTIVATED,
            active=wired,
            ip4=MockIPConfig(
                2, ["192.168.10.20/24"], "192.168.10.1", ["192.168.10.1"]
            ),
            ip6=MockIPConfig(10, ["fe80::1/64", "2001:db8::20/64"]),
        )
        wifi = MockDevice(
            "wls6",
            state=NM.DeviceState.DISCONNECTED,
            current=None,
        )
        hidden = [
            MockDevice("vif3", "ethernet", state=NM.DeviceState.ACTIVATED),
            MockDevice("ens7", "ethernet", managed=False),
            MockDevice("wg0", "wireguard"),
            MockDevice("tun0", "tun"),
        ]
        connections = [
            profile(WIRED, "ethernet", "Wired connection 1"),
            profile(HOME, "wifi", "Home", b"Home", "sae"),
            profile(VPN, "vpn", "Office VPN"),
            profile("4e5f6a7b-8c9d-4ebf-9a2b-3c4d5e6f7a8b", "wireguard", "wg"),
        ]
        client = MockClient([eth, wifi] + hidden, connections)
        client.primary = wired
        return client

    def test_devices(self):
        out = self.network(self.client()).status({})
        self.assertEqual([d["iface"] for d in out["devices"]], ["ens6", "wls6"])
        eth = out["devices"][0]
        self.assertEqual(
            eth,
            {
                "iface": "ens6",
                "type": "ethernet",
                "state": "connected",
                "profile": WIRED,
                "default4": True,
                "default6": False,
                "ipv4": {
                    "addresses": ["192.168.10.20/24"],
                    "gateway": "192.168.10.1",
                    "dns": ["192.168.10.1"],
                },
                "ipv6": {
                    "addresses": ["2001:db8::20/64"],
                    "gateway": None,
                    "dns": [],
                },
            },
        )
        self.assertIsNone(out["devices"][1]["ap"])
        self.assertEqual(out["primary"], WIRED)
        self.assertEqual(
            out["radio"], {"hardware": True, "enabled": True, "devices": 1}
        )

    def test_profiles(self):
        out = self.network(self.client()).status({})
        self.assertEqual(
            [(p["uuid"], p["type"]) for p in out["profiles"]],
            [(WIRED, "ethernet"), (HOME, "wifi")],
        )
        home = out["profiles"][1]
        self.assertEqual(home["ssid_hex"], b"Home".hex())
        self.assertEqual(home["security"], "wpa3-psk")
        self.assertEqual(out["profiles"][0]["active"], "ens6")
        self.assertNotIn(SECRET, json.dumps(out))

    def test_profile_security(self):
        n = self.network(MockClient())
        for mgmt, pmf, want in (
            (None, None, "open"),
            ("wpa-psk", None, "wpa2-psk"),
            ("sae", None, "wpa3-psk"),
            ("wpa-eap", None, "wpa2-eap"),
            ("wpa-eap", netsvc.PMF_REQUIRED, "wpa3-eap"),
            ("none", None, "wep"),
            ("owe", None, "unsupported"),
        ):
            rc = profile(HOME, "wifi", "x", b"x", mgmt, pmf)
            self.assertEqual(n._profile_security(rc), want, mgmt)

    def test_device_states(self):
        n = self.network(MockClient())
        S = NM.DeviceState
        for state, want in (
            (S.ACTIVATED, "connected"),
            (S.CONFIG, "connecting"),
            (S.IP_CHECK, "connecting"),
            (S.DEACTIVATING, "disconnecting"),
            (S.DISCONNECTED, "disconnected"),
            (S.UNAVAILABLE, "unavailable"),
            (S.FAILED, "failed"),
            (S.UNKNOWN, "unknown"),
        ):
            dev = MockDevice("wls6", state=state)
            self.assertEqual(n._state(dev), want)

    def test_profiles_left_out(self):
        client = MockClient(
            [],
            [
                profile(HOME, "wifi", "Home", b"Home"),
                profile(VPN, "wifi", "Hotspot", b"Hotspot", mode="ap"),
                profile(
                    "5e6f7a8b-9cad-4bfc-8d1e-2f3a4b5c6d7e",
                    "wifi",
                    "Shared",
                    b"Shared",
                    ipv4="shared",
                ),
                profile(
                    netsvc.QUBES_UPLINK + "0123456789ab",
                    "ethernet",
                    "VM uplink eth0",
                ),
            ],
        )
        out = self.network(client).status({})
        self.assertEqual([p["uuid"] for p in out["profiles"]], [HOME])
        with self.assertRaises(netsvc.Invalid):
            self.network(client).forget({"uuid": VPN})

    def test_profiles_limit(self):
        connections = [
            profile(
                f"{i:08x}-0000-4000-8000-000000000000",
                "wifi",
                f"net{i}",
                f"net{i}".encode(),
                timestamp=i,
            )
            for i in range(200)
        ]
        connections.append(profile(WIRED, "ethernet", "Wired connection 1"))
        eth = MockDevice(
            "ens6",
            "ethernet",
            state=NM.DeviceState.ACTIVATED,
            active=MockActive(WIRED),
        )
        out = self.network(MockClient([eth], connections)).status({})
        uuids = [p["uuid"] for p in out["profiles"]]
        self.assertEqual(len(uuids), netsvc.MAX_PROFILES)
        self.assertEqual(uuids[0], WIRED)
        self.assertEqual(uuids[1], f"{199:08x}-0000-4000-8000-000000000000")

    def test_odd_nameserver(self):
        cfg = MockIPConfig(2, ["192.168.1.20/24"], None, ["192.168.1.1", "x"])
        self.assertEqual(netsvc.Network._ip_config(cfg)["dns"], ["192.168.1.1"])

    def test_primary_only_if_shown(self):
        client = self.client()
        client.primary = MockActive(VPN)
        self.assertIsNone(self.network(client).status({})["primary"])


class Scan(Base):
    def client(self):
        aps = [
            MockAP(b"Home", 40, rsn=RSN_SAE),
            MockAP(b"Home", 80, rsn=RSN_SAE, freq=5180),
            MockAP(b"Office", 64, rsn=RSN_EAP),
            MockAP(b"Guest", 51),
            MockAP(b"Old router", 18, flags=netsvc.AP_PRIVACY),
            MockAP(b"Cafe", 33, rsn=RSN_PSK | RSN_SAE),
            MockAP(b"Mesh", 20, rsn=netsvc.SEC_OWE),
            MockAP(b"", 90, rsn=RSN_PSK),
        ]
        dev = MockDevice("wls6", aps=aps, current=aps[3])
        return MockClient(
            [dev], [profile(HOME, "wifi", "Home", b"Home", "sae")]
        )

    def test_networks(self):
        client = self.client()
        out = self.network(client).scan({"rescan": False})
        self.assertEqual(client.devices[0].scans, 0)
        nets = {bytes.fromhex(n["ssid_hex"]): n for n in out["networks"]}
        self.assertEqual(
            [bytes.fromhex(n["ssid_hex"]) for n in out["networks"]],
            [b"Guest", b"Home", b"Office", b"Cafe", b"Mesh", b"Old router"],
        )
        self.assertEqual(nets[b"Home"]["signal"], 80)
        self.assertEqual(nets[b"Home"]["frequency"], 5180)
        self.assertEqual(nets[b"Home"]["saved"], HOME)
        self.assertTrue(nets[b"Guest"]["active"])
        self.assertEqual(
            {k: v["security"] for k, v in nets.items()},
            {
                b"Home": "wpa3-psk",
                b"Office": "wpa2-eap",
                b"Guest": "open",
                b"Old router": "wep",
                b"Cafe": "wpa3-transition",
                b"Mesh": "unsupported",
            },
        )

    def test_rescan(self):
        client = self.client()
        self.network(client).scan({"rescan": True})
        self.assertEqual(client.devices[0].scans, 1)
        client.devices[0].scan_error = True
        out = self.network(client).scan({"rescan": True})
        self.assertEqual(len(out["networks"]), 6)

    def test_radio_off(self):
        client = self.client()
        client.enabled = False
        out = self.network(client).scan({"rescan": True})
        self.assertEqual(out["networks"], [])
        self.assertEqual(client.devices[0].scans, 0)

    def test_saved_first(self):
        aps = [MockAP(f"fake{i}".encode(), 99) for i in range(80)]
        aps.append(MockAP(b"Home", 10, rsn=RSN_SAE))
        client = MockClient(
            [MockDevice("wls6", aps=aps)],
            [profile(HOME, "wifi", "Home", b"Home", "sae")],
        )
        out = self.network(client).scan({"rescan": False})
        self.assertEqual(out["networks"][0]["ssid_hex"], b"Home".hex())
        self.assertEqual(len(out["networks"]), 64)

    def test_limit(self):
        aps = [MockAP(f"net{i}".encode(), i % 100) for i in range(80)]
        client = MockClient([MockDevice("wls6", aps=aps)])
        out = self.network(client).scan({"rescan": False})
        self.assertEqual(len(out["networks"]), 64)


class Connect(Base):
    def client(self, **kw):
        wifi = MockDevice("wls6", **kw)
        eth = MockDevice("ens6", "ethernet", state=NM.DeviceState.UNAVAILABLE)
        rc = profile(WIRED, "ethernet", "Wired connection 1")
        return MockClient([eth, wifi], [rc])

    def connect(self, client, obj):
        return self.network(client).connect(request("connect", obj))

    def added(self, client):
        self.assertEqual(len(client.added), 1)
        conn, flags = client.added[0]
        return conn, flags

    def test_wpa2(self):
        client = self.client()
        out = self.connect(
            client,
            {"wifi": {"ssid": "Home", "security": "wpa2-psk", "psk": SECRET}},
        )
        conn, flags = self.added(client)
        self.assertEqual(out, {"uuid": conn.get_uuid(), "state": "connected"})
        self.assertEqual(
            conn.get_id(), netsvc.profile_name(b"Home", out["uuid"])
        )
        sw = conn.get_setting_wireless()
        self.assertEqual(sw.get_ssid().get_data(), b"Home")
        self.assertEqual(sw.get_mode(), "infrastructure")
        self.assertFalse(sw.get_hidden())
        ws = conn.get_setting_wireless_security()
        self.assertEqual(ws.get_key_mgmt(), "wpa-psk")
        self.assertEqual(ws.get_psk(), SECRET)
        self.assertEqual(ws.get_psk_flags(), NM.SettingSecretFlags.NONE)
        self.assertFalse(conn.get_setting_connection().get_autoconnect())
        self.assertEqual(conn.get_setting_ip4_config().get_method(), "auto")
        self.assertEqual(conn.get_setting_ip6_config().get_method(), "auto")
        self.assertTrue(flags & NM.SettingsAddConnection2Flags.IN_MEMORY)
        self.assertFalse(flags & NM.SettingsAddConnection2Flags.TO_DISK)
        self.assertTrue(
            flags & NM.SettingsAddConnection2Flags.BLOCK_AUTOCONNECT
        )
        self.assertEqual(len(client.activated), 1)
        self.assertEqual(client.activated[0][1].get_iface(), "wls6")
        self.assertEqual(self.hook_calls(), ["- up"])
        # Saved once connected, with its secret
        rc = client.connections[-1]
        (saved,) = rc.updates
        self.assertEqual(rc.update_flags, [NM.SettingsUpdate2Flags.TO_DISK])
        self.assertTrue(saved.get_setting_connection().get_autoconnect())
        self.assertEqual(
            saved.get_setting_wireless_security().get_psk(), SECRET
        )

    def test_interrupted(self):
        client = self.client()
        n = self.network(client)
        with mock.patch.object(n, "_activate", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                n.connect(
                    request(
                        "connect",
                        {
                            "wifi": {
                                "ssid": "Home",
                                "security": "wpa2-psk",
                                "psk": SECRET,
                            }
                        },
                    )
                )
        self.assertEqual(client.connections[-1].deleted, 1)
        self.assertEqual(client.connections[-1].updates, [])

    def test_wpa3(self):
        client = self.client()
        self.connect(
            client,
            {"wifi": {"ssid": "Home", "security": "wpa3-psk", "psk": SECRET}},
        )
        ws = self.added(client)[0].get_setting_wireless_security()
        self.assertEqual(ws.get_key_mgmt(), "sae")
        self.assertEqual(int(ws.get_pmf()), netsvc.PMF_REQUIRED)

    def test_open(self):
        client = self.client()
        self.connect(
            client,
            {
                "wifi": {
                    "ssid": "Guest",
                    "security": "open",
                    "accept_open": True,
                }
            },
        )
        self.assertIsNone(self.added(client)[0].get_setting_wireless_security())

    def test_hidden_with_ip(self):
        client = self.client()
        self.connect(
            client,
            {
                "wifi": {
                    "ssid": "Lab",
                    "hidden": True,
                    "security": "wpa2-psk",
                    "psk": SECRET,
                },
                "ipv4": {
                    "method": "manual",
                    "addresses": ["192.168.74.77/24"],
                    "gateway": "192.168.74.1",
                    "dns": ["192.168.74.1"],
                    "search": ["lab.example"],
                },
                "ipv6": {"method": "disabled"},
            },
        )
        conn = self.added(client)[0]
        self.assertTrue(conn.get_setting_wireless().get_hidden())
        ip4 = conn.get_setting_ip4_config()
        self.assertEqual(ip4.get_method(), "manual")
        self.assertEqual(ip4.get_address(0).get_address(), "192.168.74.77")
        self.assertEqual(ip4.get_address(0).get_prefix(), 24)
        self.assertEqual(ip4.get_gateway(), "192.168.74.1")
        self.assertEqual(ip4.get_dns(0), "192.168.74.1")
        self.assertEqual(ip4.get_dns_search(0), "lab.example")
        self.assertEqual(conn.get_setting_ip6_config().get_method(), "disabled")

    def test_failures_forget_the_network(self):
        R = NM.DeviceStateReason
        for reason, message in (
            (R.NO_SECRETS, "wrong password or credentials"),
            (R.SUPPLICANT_DISCONNECT, "wrong password or credentials"),
            (R.SSID_NOT_FOUND, "network not found or wrong password"),
            (R.SUPPLICANT_TIMEOUT, "no answer from the network"),
            (R.IP_CONFIG_UNAVAILABLE, "no address from the network"),
            (R.CARRIER, None),
        ):
            client = self.client(reason=reason)
            client.outcome = NM.ActiveConnectionState.DEACTIVATED
            with self.assertRaises(netsvc.Failed) as cm:
                self.connect(
                    client,
                    {
                        "wifi": {
                            "ssid": "Home",
                            "security": "wpa2-psk",
                            "psk": SECRET,
                        }
                    },
                )
            want = "Failed to connect" + (f": {message}" if message else "")
            self.assertEqual(str(cm.exception), want)
            self.assertEqual(client.connections[-1].deleted, 1)
        self.assertEqual(self.hook_calls(), [])

    def test_timeout(self):
        client = self.client()
        client.outcome = NM.ActiveConnectionState.ACTIVATING
        with mock.patch.object(netsvc, "ACTIVATE_TIMEOUT", 0.2):
            with self.assertRaises(netsvc.Failed) as cm:
                self.connect(
                    client,
                    {
                        "wifi": {
                            "ssid": "Home",
                            "security": "open",
                            "accept_open": True,
                        }
                    },
                )
        self.assertEqual(
            str(cm.exception), "Failed to connect: no answer in time"
        )

    def test_refused(self):
        client = self.client()
        client.connections.append(profile(HOME, "wifi", "Home", b"Home", "sae"))
        with self.assertRaises(netsvc.Invalid) as cm:
            self.connect(
                client,
                {
                    "wifi": {
                        "ssid": "Home",
                        "security": "wpa2-psk",
                        "psk": SECRET,
                    }
                },
            )
        self.assertEqual(cm.exception.field, "wifi.ssid")
        client.enabled = False
        with self.assertRaises(netsvc.Failed) as cm:
            self.connect(
                client,
                {
                    "wifi": {
                        "ssid": "Cafe",
                        "security": "wpa2-psk",
                        "psk": SECRET,
                    }
                },
            )
        self.assertEqual(str(cm.exception), "Cannot connect: Wi-Fi is off")
        client = MockClient([MockDevice("ens6", "ethernet")])
        with self.assertRaises(netsvc.Failed) as cm:
            self.connect(
                client,
                {
                    "wifi": {
                        "ssid": "Cafe",
                        "security": "wpa2-psk",
                        "psk": SECRET,
                    }
                },
            )
        self.assertEqual(str(cm.exception), "No Wi-Fi device")
        with self.assertRaises(netsvc.Invalid) as cm:
            self.connect(
                self.client(),
                {
                    "wifi": {
                        "ssid": "Cafe",
                        "security": "wpa2-psk",
                        "psk": SECRET,
                    },
                    "device": "wls7",
                },
            )
        self.assertEqual(cm.exception.field, "device")

    def test_saved_profile(self):
        client = self.client()
        out = self.connect(client, {"uuid": WIRED})
        self.assertEqual(out, {"uuid": WIRED, "state": "connected"})
        self.assertEqual(len(client.activated), 1)
        rc, dev = client.activated[0]
        self.assertIsNone(dev)
        self.assertEqual(rc.updates, [])
        self.connect(client, {"uuid": WIRED, "device": "ens6"})
        self.assertEqual(client.activated[1][1].get_iface(), "ens6")

    def test_saved_profile_ip(self):
        client = self.client()
        self.connect(
            client,
            {
                "uuid": WIRED,
                "ipv4": {"method": "manual", "addresses": ["10.1.2.3/16"]},
                "ipv6": {
                    "method": "manual",
                    "addresses": ["2001:db8::5/64"],
                    "gateway": "2001:db8::1",
                },
            },
        )
        (update,) = client.connections[0].updates
        ip4 = update.get_setting_ip4_config()
        self.assertEqual(ip4.get_method(), "manual")
        self.assertEqual(ip4.get_address(0).get_address(), "10.1.2.3")
        self.assertEqual(ip4.get_address(0).get_prefix(), 16)
        ip6 = update.get_setting_ip6_config()
        self.assertEqual(ip6.get_address(0).get_address(), "2001:db8::5")
        self.assertEqual(ip6.get_gateway(), "2001:db8::1")
        self.assertEqual(len(client.activated), 1)

    def test_unknown_profiles(self):
        client = self.client()
        client.connections.append(profile(VPN, "vpn", "Office VPN"))
        for uuid in (HOME, VPN):
            with self.assertRaises(netsvc.Invalid) as cm:
                self.connect(client, {"uuid": uuid})
            self.assertEqual(cm.exception.field, "uuid")

    def test_secret_nowhere_else(self):
        client = self.client()
        with mock.patch.object(
            netsvc.subprocess, "run", wraps=subprocess.run
        ) as spy:
            self.connect(
                client,
                {
                    "wifi": {
                        "ssid": "Home",
                        "security": "wpa2-psk",
                        "psk": SECRET,
                    }
                },
            )
        self.assertEqual(spy.call_count, 1)
        self.assertNotIn(SECRET, repr(spy.call_args_list))
        self.assertNotIn(SECRET, repr(dict(os.environ)))
        files = [p for p in self.tmp.rglob("*") if p.is_file()]
        for f in files:
            self.assertNotIn(SECRET, f.read_text(errors="replace"))


class Disconnect(Base):
    def test_disconnect(self):
        dev = MockDevice(
            "wls6", state=NM.DeviceState.ACTIVATED, active=MockActive(HOME)
        )
        out = self.network(MockClient([dev])).disconnect({"device": "wls6"})
        self.assertEqual(out, {"state": "disconnected"})
        self.assertEqual(dev.disconnects, 1)

    def test_not_connected(self):
        dev = MockDevice("wls6")
        out = self.network(MockClient([dev])).disconnect({"device": "wls6"})
        self.assertEqual(out, {"state": "disconnected"})
        self.assertEqual(dev.disconnects, 0)

    def test_refused(self):
        devs = [
            MockDevice("vif3", "ethernet", active=MockActive(HOME)),
            MockDevice("ens7", "ethernet", managed=False),
        ]
        for name in ("vif3", "ens7", "wls9"):
            with self.assertRaises(netsvc.Invalid):
                self.network(MockClient(devs)).disconnect({"device": name})
        self.assertEqual(devs[0].disconnects, 0)

    def test_failure(self):
        dev = MockDevice("wls6", active=MockActive(HOME))
        dev.disconnect_error = True
        with self.assertRaises(netsvc.Failed) as cm:
            self.network(MockClient([dev])).disconnect({"device": "wls6"})
        self.assertEqual(str(cm.exception), "Failed to disconnect")


class Forget(Base):
    def test_forget(self):
        keyfile = self.keyfiles / "Home.nmconnection"
        keyfile.write_text("[connection]\n")
        cert = self.keyfiles / f"{HOME}-ca-cert.pem"
        cert.write_text("cert")
        other = self.keyfiles / f"{WIRED}-ca-cert.pem"
        other.write_text("cert")
        rc = profile(
            HOME, "wifi", "Home", b"Home", "sae", filename=str(keyfile)
        )
        out = self.network(MockClient([], [rc])).forget({"uuid": HOME})
        self.assertEqual(out, {"uuid": HOME})
        self.assertEqual(rc.deleted, 1)
        self.assertFalse(keyfile.exists())
        self.assertFalse(cert.exists())
        self.assertTrue(other.exists())

    def test_wifi_only(self):
        rc = profile(WIRED, "ethernet", "Wired connection 1")
        with self.assertRaises(netsvc.Invalid):
            self.network(MockClient([], [rc])).forget({"uuid": WIRED})
        self.assertEqual(rc.deleted, 0)

    def test_file_left(self):
        keyfile = self.keyfiles / "Home.nmconnection"
        keyfile.write_text("[connection]\n")
        rc = profile(
            HOME, "wifi", "Home", b"Home", "sae", filename=str(keyfile)
        )
        rc.keep_file = True
        n = self.network(MockClient([], [rc]))
        with mock.patch.object(n, "_spin", lambda done, timeout: done()):
            with self.assertRaises(netsvc.Failed) as cm:
                n.forget({"uuid": HOME})
        self.assertEqual(str(cm.exception), "Failed to forget the network")


class Radio(Base):
    def test_radio(self):
        client = MockClient([MockDevice("wls6")])
        out = self.network(client).radio({"enabled": False})
        self.assertEqual(
            client.properties,
            [(NM.DBUS_PATH, NM.DBUS_INTERFACE, "WirelessEnabled", False)],
        )
        self.assertFalse(out["radio"]["enabled"])

    def test_no_device(self):
        client = MockClient([MockDevice("ens6", "ethernet")])
        with self.assertRaises(netsvc.Failed) as cm:
            self.network(client).radio({"enabled": True})
        self.assertEqual(str(cm.exception), "No Wi-Fi device")
        self.assertEqual(client.properties, [])


class Main(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.held = []
        self.addCleanup(lambda: [os.close(fd) for fd in self.held])

    def hold(self, path):
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.held.append(fd)

    def run_main(self, verb, data=b"{}", env=None, **kw):
        calls, logs, flocks, alarms, handlers = [], [], [], [], {}

        class MockNetwork:
            def __getattr__(self, name):
                def method(req):
                    calls.append((name, req))
                    if "during" in kw:
                        kw["during"](handlers)
                    if "error" in kw:
                        raise kw["error"]
                    return kw.get("result", {})

                return method

        real_flock = fcntl.flock

        def flock(fd, op):
            flocks.append(op)
            return real_flock(fd, op)

        out = io.StringIO()
        environ = {"QREXEC_REMOTE_DOMAIN": "sys-gui-alice"}
        environ.update(env or {})
        hook = sys.excepthook
        with mock.patch.multiple(
            netsvc,
            harden=mock.DEFAULT,
            Network=MockNetwork,
            LOCK=str(self.tmp / "lock"),
            SLOT=str(self.tmp / "slot{}"),
            LOCK_TIMEOUT=0.3,
            read_input=mock.Mock(return_value=data),
        ), mock.patch.object(
            netsvc.signal, "alarm", alarms.append
        ), mock.patch.object(
            netsvc.signal, "signal", handlers.__setitem__
        ), mock.patch.object(
            netsvc.syslog, "syslog", lambda _p, text: logs.append(text)
        ), mock.patch.object(
            netsvc.fcntl, "flock", flock
        ), mock.patch.object(
            sys, "argv", ["netsvc", verb]
        ), mock.patch.dict(
            os.environ, environ, clear=True
        ), redirect_stdout(
            out
        ):
            rc = netsvc.main()
        sys.excepthook = hook
        lock = self.tmp / "lock"
        return types.SimpleNamespace(
            rc=rc,
            answer=json.loads(out.getvalue()),
            calls=calls,
            logs=logs,
            flocks=flocks,
            alarms=alarms,
            mode=lock.stat().st_mode & 0o777 if lock.exists() else None,
        )

    def test_status_takes_no_lock(self):
        r = self.run_main("status", result={"devices": []})
        self.assertEqual((r.rc, r.answer), (0, {"ok": True, "devices": []}))
        self.assertEqual(r.calls, [("status", {})])
        self.assertEqual(r.logs, [])
        nb = fcntl.LOCK_EX | fcntl.LOCK_NB
        self.assertEqual(r.flocks, [nb])
        self.assertEqual(r.alarms, [netsvc.TIMEOUT, 0])

    def test_change_takes_lock_and_logs(self):
        r = self.run_main(
            "forget", json.dumps({"uuid": HOME}).encode(), result={"uuid": HOME}
        )
        self.assertEqual((r.rc, r.answer["ok"]), (0, True))
        nb = fcntl.LOCK_EX | fcntl.LOCK_NB
        self.assertEqual(r.flocks, [nb, nb])
        self.assertEqual(r.mode, 0o600)
        self.assertEqual(
            r.logs, [f"forget from sys-gui-alice: OK, uuid '{HOME}'"]
        )
        r = self.run_main("radio", b'{"enabled": true}', result={"radio": {}})
        self.assertEqual(r.logs, ["radio from sys-gui-alice: OK"])
        r = self.run_main(
            "disconnect", b'{"device": "wls6"}', result={"state": "x"}
        )
        self.assertEqual(
            r.logs, ["disconnect from sys-gui-alice: OK, device 'wls6'"]
        )

    def test_failure_logged(self):
        r = self.run_main(
            "radio",
            b'{"enabled": true}',
            error=netsvc.Failed("No Wi-Fi device"),
        )
        self.assertEqual(r.rc, 1)
        self.assertEqual(r.answer, {"ok": False, "error": "No Wi-Fi device"})
        self.assertEqual(r.logs, ["radio from sys-gui-alice: No Wi-Fi device"])

    def test_refused_before_network(self):
        for verb, data, env, error in (
            (
                "status",
                b"{}",
                {"QREXEC_SERVICE_ARGUMENT": "x"},
                "Invalid 'service': takes no argument",
            ),
            ("reboot", b"{}", {}, "Invalid 'service'"),
            ("status", b'{"x": 1}', {}, "Invalid 'document': unknown key"),
        ):
            r = self.run_main(verb, data, env)
            self.assertEqual(
                (r.rc, r.answer), (1, {"ok": False, "error": error})
            )
            self.assertEqual(r.calls, [])
            self.assertEqual(len(r.logs), 1)
        r = self.run_main(
            "status", b"[]", {"QREXEC_REMOTE_DOMAIN": "bad name!"}
        )
        self.assertTrue(r.logs[0].startswith("status from ?: Invalid"))

    def test_too_many_calls(self):
        for i in range(netsvc.SLOTS):
            self.hold(self.tmp / f"slot{i}")
        r = self.run_main("status")
        self.assertEqual(
            r.answer,
            {"ok": False, "error": "Cannot answer now: too many calls"},
        )
        self.assertEqual(r.calls, [])

    def test_lock_busy(self):
        self.hold(self.tmp / "lock")
        r = self.run_main("radio", b'{"enabled": true}')
        self.assertEqual(r.rc, 1)
        self.assertEqual(
            r.answer["error"], "Cannot change the network now: try again"
        )
        self.assertEqual(r.calls, [])
        self.assertNotIn(netsvc.TIMEOUT, r.alarms)

    def test_timeout_cleans_up(self):
        def expire(handlers):
            handlers[netsvc.signal.SIGALRM]()

        r = self.run_main("radio", b'{"enabled": true}', during=expire)
        self.assertEqual(
            r.answer, {"ok": False, "error": "Failed to answer in time"}
        )
        self.assertEqual(
            r.logs, ["radio from sys-gui-alice: Failed to answer in time"]
        )
        self.assertEqual(r.alarms, [netsvc.TIMEOUT, 10, 0])

    def test_input_deadline(self):
        r, w = os.pipe()
        self.addCleanup(os.close, r)
        with self.assertRaises(netsvc.Invalid) as cm:
            netsvc.read_input(r, timeout=0.2)
        self.assertEqual(
            str(cm.exception), "Invalid 'document': not sent in time"
        )
        os.write(w, b"{}")
        os.close(w)
        self.assertEqual(netsvc.read_input(r, timeout=1), b"{}")

    def test_process(self):
        code = (
            "import ctypes, importlib.util, os, resource, sys;"
            f"s = importlib.util.spec_from_file_location('n', {str(SVC)!r});"
            "n = importlib.util.module_from_spec(s); s.loader.exec_module(n);"
            "n.harden();"
            "libc = ctypes.CDLL(None);"
            "u = os.umask(0); "
            "core = resource.getrlimit(resource.RLIMIT_CORE);"
            "print(core, libc.prctl(3, 0, 0, 0, 0), oct(u))"
        )
        out = subprocess.run(
            [sys.executable, "-I", "-c", code],
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        self.assertEqual(out, "(0, 0) 0 0o77")

    def test_input_limit(self):
        env = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS="unix:path=/nonexistent")
        for verb, data, want in (
            ("status", b" " * (65 * 1024), "Invalid 'document': too large"),
            ("status", b"{}", "Failed to run the request"),
        ):
            p = subprocess.run(
                [sys.executable, "-I", str(SVC), verb],
                input=data,
                capture_output=True,
                env=env,
                check=False,
            )
            self.assertEqual(json.loads(p.stdout), {"ok": False, "error": want})
            self.assertEqual(p.returncode, 1)


if __name__ == "__main__":
    unittest.main()
