#!/usr/bin/python3 -I
"""
Network services of the network qube for the network widget
"""

import ctypes
import fcntl
import ipaddress
import json
import os
import re
import resource
import select
import signal
import subprocess
import sys
import syslog
import time
import uuid as uuidlib

MAX_INPUT = 64 * 1024
LOCK = "/run/qubes-net-widget.lock"
SLOT = "/run/qubes-net-widget.slot{}"
SLOTS = 8
LOCK_TIMEOUT = 30
INPUT_TIMEOUT = 10
MAX_PROFILES = 128
# Uplink profile of a Qubes network qube
QUBES_UPLINK = "de85f79b-8c3d-405f-a652-"
HOOK = "/etc/NetworkManager/dispatcher.d/90-qubes-net-conntrack"
KEYFILES = "/etc/NetworkManager/system-connections"
TIMEOUT = 100
ACTIVATE_TIMEOUT = 60
SCAN_TIMEOUT = 12

VERBS = ("status", "scan", "connect", "disconnect", "forget", "radio")
SECURITIES = ("open", "wpa2-psk", "wpa3-psk")
QUBES_NETS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.137.0.0/16",
        "10.138.0.0/16",
        "10.139.0.0/16",
        "fd09:24ef:4179::/48",
    )
)
UUID_RE = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
)
IFACE_RE = re.compile(r"[a-z][a-z0-9]{0,14}")
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
SSID_HEX_RE = re.compile(r"(?:[0-9a-f]{2}){1,32}")
PSK_HEX_RE = re.compile(r"[0-9a-fA-F]{64}")
IP_CHARS = {4: re.compile(r"[0-9./]+"), 6: re.compile(r"[0-9a-fA-F:./]+")}
DOMAIN_RE = re.compile(r"[A-Za-z0-9_.-]{1,31}")

# NetworkManager's 802.11 flags, stable in its D-Bus API
AP_PRIVACY = 0x1
SEC_PSK = 0x100
SEC_8021X = 0x200
SEC_SAE = 0x400
SEC_OWE = 0x800 | 0x1000
SEC_SUITE_B = 0x2000
PMF_REQUIRED = 3


class Invalid(Exception):
    """
    Invalid request field, named but never quoted
    """

    def __init__(self, field, reason=""):
        super().__init__(field)
        self.field = field
        self.reason = reason

    def __str__(self):
        text = f"Invalid '{self.field}'"
        return f"{text}: {self.reason}" if self.reason else text


class Failed(Exception):
    """
    Failed operation with a fixed message
    """


def _path(parent, key):
    return f"{parent}.{key}" if parent else key


def _keys(obj, field, required=(), optional=()):
    if not isinstance(obj, dict):
        raise Invalid(field or "document", "not an object")
    for key in obj:
        if key not in required and key not in optional:
            raise Invalid(field or "document", "unknown key")
    for key in required:
        if key not in obj:
            raise Invalid(_path(field, key), "missing")


def _bool(obj, key, field, default=None):
    if key not in obj:
        if default is None:
            raise Invalid(_path(field, key), "missing")
        return default
    if not isinstance(obj[key], bool):
        raise Invalid(_path(field, key), "not true or false")
    return obj[key]


def _text(value, field, maxlen, minlen=1):
    """
    Text with no control, format or surrogate character
    """
    if not isinstance(value, str) or not minlen <= len(value) <= maxlen:
        raise Invalid(field)
    if not value.isprintable():
        raise Invalid(field, "control character")
    return value


def _list(obj, key, field, maxlen):
    value = obj.get(key, [])
    if not isinstance(value, list) or len(value) > maxlen:
        raise Invalid(_path(field, key), f"a list of at most {maxlen}")
    return value


def _forbidden(ip):
    if ip.is_unspecified or ip.is_loopback or ip.is_multicast:
        return True
    if ip.is_reserved:
        return True
    if ip.version == 6 and (ip.is_site_local or ip.ipv4_mapped is not None):
        return True
    return any(ip in net for net in QUBES_NETS)


def _ip_address(value, field, version, link_local=False):
    if not isinstance(value, str) or len(value) > 45:
        raise Invalid(field)
    if not IP_CHARS[version].fullmatch(value) or "/" in value:
        raise Invalid(field)
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        raise Invalid(field) from None
    if ip.version != version or _forbidden(ip):
        raise Invalid(field)
    if ip.is_link_local and not (link_local and version == 6):
        raise Invalid(field)
    return ip


def _ip_interface(value, field, version):
    if not isinstance(value, str) or len(value) > 49:
        raise Invalid(field)
    if not IP_CHARS[version].fullmatch(value) or value.count("/") != 1:
        raise Invalid(field, "an address with its prefix")
    address, _, prefix = value.partition("/")
    if not prefix.isdigit() or prefix.startswith("0"):
        raise Invalid(field, "an address with its prefix")
    if not 1 <= int(prefix) <= (32 if version == 4 else 128):
        raise Invalid(field, "prefix out of range")
    ip = _ip_address(address, field, version)
    iface = ipaddress.ip_interface(f"{ip}/{prefix}")
    net = iface.network
    if version == 4 and net.prefixlen < 31:
        if ip in (net.network_address, net.broadcast_address):
            raise Invalid(field, "network or broadcast address")
    return iface


def _domain(value, field):
    if not isinstance(value, str) or not 1 <= len(value) <= 253:
        raise Invalid(field)
    if not all(LABEL_RE.fullmatch(label) for label in value.split(".")):
        raise Invalid(field, "lowercase letters, digits, '-' and '.'")
    return value


def _ip(obj, version):
    field = f"ipv{version}"
    methods = ("auto", "manual", "disabled")
    if version == 6:
        methods += ("dhcp",)
    _keys(obj, field, ("method",), ("addresses", "gateway", "dns", "search"))
    method = obj["method"]
    if not isinstance(method, str) or method not in methods:
        raise Invalid(f"{field}.method")
    allowed = {
        "manual": ("addresses", "gateway", "dns", "search"),
        "auto": ("dns", "search"),
        "dhcp": ("dns", "search"),
        "disabled": (),
    }[method]
    for key in obj:
        if key != "method" and key not in allowed:
            raise Invalid(f"{field}.{key}", f"not with method '{method}'")
    out = {"method": method, "addresses": [], "gateway": None}
    for i, value in enumerate(_list(obj, "addresses", field, 4)):
        iface = _ip_interface(value, f"{field}.addresses[{i}]", version)
        if any(iface.ip == a.ip for a in out["addresses"]):
            raise Invalid(f"{field}.addresses[{i}]", "duplicate")
        out["addresses"].append(iface)
    if method == "manual" and not out["addresses"]:
        raise Invalid(f"{field}.addresses", "missing")
    if "gateway" in obj:
        gw = _ip_address(obj["gateway"], f"{field}.gateway", version, True)
        nets = [a.network for a in out["addresses"]]
        if not gw.is_link_local and not any(gw in n for n in nets):
            raise Invalid(f"{field}.gateway", "outside the addresses")
        if any(gw == a.ip for a in out["addresses"]):
            raise Invalid(f"{field}.gateway", "one of the addresses")
        if version == 4:
            for a in out["addresses"]:
                net = a.network
                if net.prefixlen < 31 and gw in (
                    net.network_address,
                    net.broadcast_address,
                ):
                    raise Invalid(f"{field}.gateway")
        out["gateway"] = gw
    out["dns"] = []
    for i, value in enumerate(_list(obj, "dns", field, 3)):
        ip = _ip_address(value, f"{field}.dns[{i}]", version)
        if ip in out["dns"]:
            raise Invalid(f"{field}.dns[{i}]", "duplicate")
        out["dns"].append(ip)
    out["search"] = []
    for i, value in enumerate(_list(obj, "search", field, 6)):
        name = _domain(value, f"{field}.search[{i}]")
        if name in out["search"]:
            raise Invalid(f"{field}.search[{i}]", "duplicate")
        out["search"].append(name)
    return out


def _ssid(wifi):
    if ("ssid" in wifi) == ("ssid_hex" in wifi):
        raise Invalid("wifi.ssid", "give 'ssid' or 'ssid_hex'")
    if "ssid_hex" in wifi:
        value = wifi["ssid_hex"]
        if not isinstance(value, str) or not SSID_HEX_RE.fullmatch(value):
            raise Invalid("wifi.ssid_hex")
        return bytes.fromhex(value)
    raw = _text(wifi["ssid"], "wifi.ssid", 32).encode()
    if len(raw) > 32:
        raise Invalid("wifi.ssid", "longer than 32 bytes")
    return raw


def _psk(value, sae):
    if not isinstance(value, str):
        raise Invalid("wifi.psk")
    if len(value) == 64 and PSK_HEX_RE.fullmatch(value):
        if sae:
            raise Invalid("wifi.psk", "WPA3 takes a passphrase")
        return value
    if 8 <= len(value) <= 63 and all(" " <= c <= "~" for c in value):
        return value
    raise Invalid(
        "wifi.psk", "8 to 63 printable ASCII characters or 64 hex digits"
    )


def _wifi(obj):
    field = "wifi"
    _keys(
        obj,
        field,
        ("security",),
        ("ssid", "ssid_hex", "hidden", "psk", "accept_open"),
    )
    out = {"ssid": _ssid(obj), "hidden": _bool(obj, "hidden", field, False)}
    security = obj["security"]
    if not isinstance(security, str) or security not in SECURITIES:
        raise Invalid("wifi.security", "unsupported")
    out["security"] = security
    kind = security.rpartition("-")[2]
    for key, needed in (
        ("accept_open", kind == "open"),
        ("psk", kind == "psk"),
    ):
        if needed and key not in obj:
            raise Invalid(f"{field}.{key}", "missing")
        if not needed and key in obj:
            raise Invalid(f"{field}.{key}", f"not with '{security}'")
    if kind == "open" and not _bool(obj, "accept_open", field):
        raise Invalid("wifi.accept_open", "an open network needs it")
    if kind == "psk":
        out["psk"] = _psk(obj["psk"], security == "wpa3-psk")
    return out


def _uuid(value, field="uuid"):
    if not isinstance(value, str) or not UUID_RE.fullmatch(value):
        raise Invalid(field)
    return value


def _iface(value, field="device"):
    if not isinstance(value, str) or not IFACE_RE.fullmatch(value):
        raise Invalid(field)
    if value.startswith("vif") or value == "lo":
        raise Invalid(field)
    return value


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Invalid("document", "duplicate key")
        out[key] = value
    return out


def _constant(_name):
    raise Invalid("document", "not a number")


def parse(data):
    """
    One JSON object, strict
    """
    if len(data) > MAX_INPUT:
        raise Invalid("document", "too large")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        raise Invalid("document", "not UTF-8") from None
    try:
        doc = json.loads(
            text, object_pairs_hook=_pairs, parse_constant=_constant
        )
    except (ValueError, RecursionError):
        raise Invalid("document", "not JSON") from None
    if not isinstance(doc, dict):
        raise Invalid("document", "not an object")
    return doc


def validate(verb, doc):
    """
    Validate the whole request
    """
    if verb == "status":
        _keys(doc, "")
        return {}
    if verb == "scan":
        _keys(doc, "", (), ("rescan",))
        return {"rescan": _bool(doc, "rescan", "", True)}
    if verb == "radio":
        _keys(doc, "", ("enabled",))
        return {"enabled": _bool(doc, "enabled", "")}
    if verb == "disconnect":
        _keys(doc, "", ("device",))
        return {"device": _iface(doc["device"])}
    if verb == "forget":
        _keys(doc, "", ("uuid",))
        return {"uuid": _uuid(doc["uuid"])}
    if verb == "connect":
        _keys(doc, "", (), ("uuid", "wifi", "device", "ipv4", "ipv6"))
        if ("uuid" in doc) == ("wifi" in doc):
            raise Invalid("document", "give 'uuid' or 'wifi'")
        out = {
            "uuid": _uuid(doc["uuid"]) if "uuid" in doc else None,
            "wifi": _wifi(doc["wifi"]) if "wifi" in doc else None,
            "device": _iface(doc["device"]) if "device" in doc else None,
            "ipv4": _ip(doc["ipv4"], 4) if "ipv4" in doc else None,
            "ipv6": _ip(doc["ipv6"], 6) if "ipv6" in doc else None,
        }
        return out
    raise Invalid("service", "unsupported")


def profile_name(ssid, uuid):
    """
    NetworkManager id of a new Wi-Fi profile
    """
    text = ssid.decode("ascii", "replace")
    safe = re.sub(r"[^A-Za-z0-9_-]+", "-", text).strip("-")[:20]
    return f"wifi-{safe or 'network'}-{uuid[:8]}"


def ap_security(flags, wpa, rsn):
    keys = int(wpa) | int(rsn)
    if keys & SEC_SUITE_B:
        return "unsupported"
    if keys & SEC_8021X:
        return "wpa2-eap"
    if keys & SEC_SAE and keys & SEC_PSK:
        return "wpa3-transition"
    if keys & SEC_SAE:
        return "wpa3-psk"
    if keys & SEC_PSK:
        return "wpa2-psk"
    if keys & SEC_OWE:
        return "unsupported"
    if int(flags) & AP_PRIVACY:
        return "wep"
    return "open"


class Network:
    """
    NetworkManager over D-Bus, as root
    """

    def __init__(self):
        import gi

        gi.require_version("NM", "1.0")
        from gi.repository import GLib, NM

        self.GLib = GLib
        self.NM = NM
        self.client = NM.Client.new(None)

    def _spin(self, done, timeout):
        ctx = self.GLib.MainContext.default()
        tick = self.GLib.timeout_add(100, lambda: True)
        end = time.monotonic() + timeout
        try:
            while not done() and time.monotonic() < end:
                ctx.iteration(True)
        finally:
            self.GLib.source_remove(tick)
        return done()

    def _call(self, start, finish, message, timeout=30):
        box = {}

        def done(_source, result, *_):
            try:
                box["value"] = finish(result)
            except self.GLib.Error:
                box["error"] = True

        start(done)
        if not self._spin(lambda: box, timeout) or "error" in box:
            raise Failed(message)
        return box["value"]

    def devices(self, kind=None):
        NM = self.NM
        kinds = {
            NM.DeviceType.ETHERNET: "ethernet",
            NM.DeviceType.WIFI: "wifi",
        }
        out = []
        for dev in self.client.get_devices():
            name = kinds.get(dev.get_device_type())
            iface = dev.get_iface() or ""
            if name is None or not dev.get_managed():
                continue
            if not IFACE_RE.fullmatch(iface) or iface.startswith("vif"):
                continue
            if kind is None or kind == name:
                out.append((name, dev))
        return sorted(out, key=lambda d: d[1].get_iface())

    def profiles(self):
        kinds = {"802-3-ethernet": "ethernet", "802-11-wireless": "wifi"}
        out = []
        for rc in self.client.get_connections():
            kind = kinds.get(rc.get_connection_type())
            uuid = rc.get_uuid() or ""
            if not kind or not UUID_RE.fullmatch(uuid):
                continue
            if uuid.startswith(QUBES_UPLINK):
                continue
            sw = rc.get_setting_wireless()
            if kind == "wifi" and (
                sw is None
                or (sw.get_mode() or "infrastructure") != "infrastructure"
            ):
                continue
            ip4 = rc.get_setting_ip4_config()
            if ip4 is not None and ip4.get_method() == "shared":
                continue
            out.append((kind, rc))
        return out

    def profile(self, uuid, kinds=("ethernet", "wifi")):
        for kind, rc in self.profiles():
            if rc.get_uuid() == uuid and kind in kinds:
                return kind, rc
        raise Invalid("uuid", "no such connection")

    def _state(self, dev):
        S = self.NM.DeviceState
        state = dev.get_state()
        if state == S.ACTIVATED:
            return "connected"
        if state in (
            S.PREPARE,
            S.CONFIG,
            S.NEED_AUTH,
            S.IP_CONFIG,
            S.IP_CHECK,
            S.SECONDARIES,
        ):
            return "connecting"
        return {
            S.DEACTIVATING: "disconnecting",
            S.DISCONNECTED: "disconnected",
            S.UNAVAILABLE: "unavailable",
            S.FAILED: "failed",
        }.get(state, "unknown")

    @staticmethod
    def _ip_config(cfg):
        if cfg is None:
            return {"addresses": [], "gateway": None, "dns": []}
        addresses = []
        for a in cfg.get_addresses():
            ip = ipaddress.ip_address(a.get_address())
            if not ip.is_link_local:
                addresses.append(f"{ip}/{a.get_prefix()}")
        dns = []
        for n in cfg.get_nameservers():
            try:
                dns.append(str(ipaddress.ip_address(n)))
            except ValueError:
                continue
        return {
            "addresses": addresses,
            "gateway": cfg.get_gateway() or None,
            "dns": dns,
        }

    @staticmethod
    def _ip_setting(setting):
        methods = {
            "auto": "auto",
            "dhcp": "dhcp",
            "manual": "manual",
            "disabled": "disabled",
            "ignore": "disabled",
        }
        if setting is None:
            return {"method": "auto"}
        out = {"method": methods.get(setting.get_method(), "other")}
        out["addresses"] = [
            f"{a.get_address()}/{a.get_prefix()}"
            for a in (
                setting.get_address(i)
                for i in range(setting.get_num_addresses())
            )
        ]
        out["gateway"] = setting.get_gateway() or None
        out["dns"] = [setting.get_dns(i) for i in range(setting.get_num_dns())]
        out["search"] = [
            setting.get_dns_search(i)
            for i in range(setting.get_num_dns_searches())
        ]
        return out

    def _profile_security(self, rc):
        sec = rc.get_setting_wireless_security()
        if sec is None:
            return "open"
        mgmt = sec.get_key_mgmt()
        if mgmt == "wpa-psk":
            return "wpa2-psk"
        if mgmt == "sae":
            return "wpa3-psk"
        if mgmt == "wpa-eap":
            pmf = int(sec.get_pmf())
            return "wpa3-eap" if pmf == PMF_REQUIRED else "wpa2-eap"
        if mgmt == "none":
            return "wep"
        return "unsupported"

    def status(self, _req):
        active = {}
        for ac in self.client.get_active_connections():
            active[ac.get_uuid()] = ac
        primary = self.client.get_primary_connection()
        devices = []
        by_profile = {}
        for kind, dev in self.devices():
            ac = dev.get_active_connection()
            uuid = ac.get_uuid() if ac is not None else None
            entry = {
                "iface": dev.get_iface(),
                "type": kind,
                "state": self._state(dev),
                "profile": uuid if uuid and UUID_RE.fullmatch(uuid) else None,
                "default4": bool(ac is not None and ac.get_default()),
                "default6": bool(ac is not None and ac.get_default6()),
                "ipv4": self._ip_config(dev.get_ip4_config()),
                "ipv6": self._ip_config(dev.get_ip6_config()),
            }
            if kind == "wifi":
                ap = dev.get_active_access_point()
                entry["ap"] = self._ap(ap) if ap is not None else None
            if entry["profile"]:
                by_profile[entry["profile"]] = entry["iface"]
            devices.append(entry)
        profiles = []
        found = sorted(
            self.profiles(),
            key=lambda p: (
                p[1].get_uuid() not in by_profile,
                -p[1].get_setting_connection().get_timestamp(),
            ),
        )
        for kind, rc in found[:MAX_PROFILES]:
            sc = rc.get_setting_connection()
            entry = {
                "uuid": rc.get_uuid(),
                "type": kind,
                "name": (rc.get_id() or "")[:64],
                "autoconnect": bool(sc.get_autoconnect()),
                "saved": not rc.get_unsaved(),
                "active": by_profile.get(rc.get_uuid()),
                "ipv4": self._ip_setting(rc.get_setting_ip4_config()),
                "ipv6": self._ip_setting(rc.get_setting_ip6_config()),
            }
            if kind == "wifi":
                sw = rc.get_setting_wireless()
                ssid = sw.get_ssid() if sw is not None else None
                entry["ssid_hex"] = ssid.get_data().hex() if ssid else ""
                entry["hidden"] = bool(sw.get_hidden()) if sw else False
                entry["security"] = self._profile_security(rc)
            profiles.append(entry)
        return {
            "radio": self._radio(),
            "devices": devices,
            "profiles": profiles,
            "primary": (
                primary.get_uuid()
                if primary is not None and primary.get_uuid() in by_profile
                else None
            ),
        }

    def _radio(self):
        return {
            "hardware": bool(self.client.wireless_hardware_get_enabled()),
            "enabled": bool(self.client.wireless_get_enabled()),
            "devices": len(self.devices("wifi")),
        }

    @staticmethod
    def _ap(ap):
        ssid = ap.get_ssid()
        return {
            "ssid_hex": ssid.get_data().hex() if ssid else "",
            "signal": max(0, min(100, int(ap.get_strength()))),
            "frequency": int(ap.get_frequency()),
            "security": ap_security(
                ap.get_flags(), ap.get_wpa_flags(), ap.get_rsn_flags()
            ),
        }

    def scan(self, req):
        radio = self._radio()
        devs = [d for _, d in self.devices("wifi")]
        if not devs or not radio["enabled"]:
            return {"radio": radio, "networks": []}
        if req["rescan"]:
            for dev in devs:
                before = dev.get_last_scan()
                try:
                    self._call(
                        lambda cb, d=dev: d.request_scan_async(None, cb),
                        dev.request_scan_finish,
                        "Failed to scan",
                    )
                except Failed:
                    continue
                self._spin(
                    lambda d=dev, b=before: d.get_last_scan() != b, SCAN_TIMEOUT
                )
        saved = {}
        for kind, rc in self.profiles():
            sw = rc.get_setting_wireless() if kind == "wifi" else None
            ssid = sw.get_ssid() if sw is not None else None
            if ssid:
                saved.setdefault(ssid.get_data().hex(), rc.get_uuid())
        current = set()
        networks = {}
        for dev in devs:
            ap = dev.get_active_access_point()
            if ap is not None and ap.get_ssid():
                current.add(ap.get_ssid().get_data().hex())
            for ap in dev.get_access_points():
                entry = self._ap(ap)
                if not entry["ssid_hex"]:
                    continue
                old = networks.get(entry["ssid_hex"])
                if old is None or old["signal"] < entry["signal"]:
                    networks[entry["ssid_hex"]] = entry
        out = []
        for key, entry in networks.items():
            entry["saved"] = saved.get(key)
            entry["active"] = key in current
            out.append(entry)
        # Saved networks first against beacon floods
        out.sort(key=lambda e: (-e["active"], e["saved"] is None, -e["signal"]))
        return {"radio": self._radio(), "networks": out[:64]}

    def _apply_ip(self, setting, family, cfg):
        NM = self.NM
        setting.set_property(NM.SETTING_IP_CONFIG_METHOD, cfg["method"])
        setting.clear_addresses()
        setting.clear_dns()
        setting.clear_dns_searches()
        setting.set_property(NM.SETTING_IP_CONFIG_GATEWAY, None)
        for a in cfg["addresses"]:
            setting.add_address(
                NM.IPAddress.new(family, str(a.ip), a.network.prefixlen)
            )
        if cfg["gateway"] is not None:
            setting.set_property(
                NM.SETTING_IP_CONFIG_GATEWAY, str(cfg["gateway"])
            )
        for ip in cfg["dns"]:
            setting.add_dns(str(ip))
        for name in cfg["search"]:
            setting.add_dns_search(name)

    def _set_ip(self, conn, req):
        NM = self.NM
        for key, family, getter, new in (
            ("ipv4", 2, conn.get_setting_ip4_config, NM.SettingIP4Config.new),
            ("ipv6", 10, conn.get_setting_ip6_config, NM.SettingIP6Config.new),
        ):
            if req.get(key) is None:
                continue
            setting = getter()
            if setting is None:
                setting = new()
                conn.add_setting(setting)
            self._apply_ip(setting, family, req[key])

    def _wifi_connection(self, wifi, req):
        NM, GLib = self.NM, self.GLib
        uuid = str(uuidlib.uuid4())
        conn = NM.SimpleConnection.new()
        sc = NM.SettingConnection.new()
        sc.set_property(
            NM.SETTING_CONNECTION_ID, profile_name(wifi["ssid"], uuid)
        )
        sc.set_property(NM.SETTING_CONNECTION_UUID, uuid)
        sc.set_property(NM.SETTING_CONNECTION_TYPE, "802-11-wireless")
        sc.set_property(NM.SETTING_CONNECTION_AUTOCONNECT, False)
        conn.add_setting(sc)
        sw = NM.SettingWireless.new()
        sw.set_property(NM.SETTING_WIRELESS_SSID, GLib.Bytes.new(wifi["ssid"]))
        sw.set_property(NM.SETTING_WIRELESS_MODE, "infrastructure")
        sw.set_property(NM.SETTING_WIRELESS_HIDDEN, wifi["hidden"])
        conn.add_setting(sw)
        security = wifi["security"]
        none = NM.SettingSecretFlags.NONE
        if security != "open":
            ws = NM.SettingWirelessSecurity.new()
            mgmt = {"wpa2-psk": "wpa-psk", "wpa3-psk": "sae"}[security]
            ws.set_property(NM.SETTING_WIRELESS_SECURITY_KEY_MGMT, mgmt)
            if security.startswith("wpa3"):
                ws.set_property(NM.SETTING_WIRELESS_SECURITY_PMF, PMF_REQUIRED)
            if "psk" in wifi:
                ws.set_property(NM.SETTING_WIRELESS_SECURITY_PSK, wifi["psk"])
                ws.set_property(NM.SETTING_WIRELESS_SECURITY_PSK_FLAGS, none)
            conn.add_setting(ws)
        conn.add_setting(NM.SettingIP4Config.new())
        conn.add_setting(NM.SettingIP6Config.new())
        for setting in (
            conn.get_setting_ip4_config(),
            conn.get_setting_ip6_config(),
        ):
            setting.set_property(NM.SETTING_IP_CONFIG_METHOD, "auto")
        self._set_ip(conn, req)
        try:
            conn.normalize()
            conn.verify()
            conn.verify_secrets()
        except GLib.Error:
            raise Invalid("wifi") from None
        return uuid, conn

    def _activate(self, rc, dev):
        NM = self.NM
        c = self.client
        ac = self._call(
            lambda cb: c.activate_connection_async(rc, dev, None, None, cb),
            c.activate_connection_finish,
            "Failed to connect",
        )
        S = NM.ActiveConnectionState
        if not self._spin(
            lambda: ac.get_state() in (S.ACTIVATED, S.DEACTIVATED),
            ACTIVATE_TIMEOUT,
        ):
            raise Failed("Failed to connect: no answer in time")
        if ac.get_state() == S.ACTIVATED:
            self._flush()
            return
        reason = dev.get_state_reason() if dev is not None else None
        R = NM.DeviceStateReason
        if reason in (R.NO_SECRETS, R.SUPPLICANT_DISCONNECT):
            raise Failed("Failed to connect: wrong password or credentials")
        if reason == R.SSID_NOT_FOUND:
            # WPA3 reports a wrong password this way too
            raise Failed(
                "Failed to connect: network not found or wrong password"
            )
        if reason in (R.SUPPLICANT_TIMEOUT, R.SUPPLICANT_FAILED):
            raise Failed("Failed to connect: no answer from the network")
        if reason in (R.IP_CONFIG_UNAVAILABLE, R.IP_CONFIG_EXPIRED):
            raise Failed("Failed to connect: no address from the network")
        raise Failed("Failed to connect")

    @staticmethod
    def _flush():
        """
        Drop flows NATed during the change
        """
        if os.access(HOOK, os.X_OK):
            subprocess.run(
                [HOOK, "-", "up"],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=20,
                check=False,
            )

    def _device_for(self, kind, name):
        devs = self.devices(kind)
        if name is not None:
            devs = [d for d in devs if d[1].get_iface() == name]
            if not devs:
                raise Invalid("device", f"no such {kind} device")
        if not devs and kind == "wifi":
            raise Failed("No Wi-Fi device")
        # NetworkManager picks the Ethernet device of a profile
        if name is None and kind == "ethernet":
            return None
        return devs[0][1]

    def _delete(self, rc):
        filename = rc.get_filename() or ""
        uuid = rc.get_uuid()
        self._call(
            lambda cb: rc.delete_async(None, cb),
            rc.delete_finish,
            "Failed to forget the network",
        )
        self._spin(lambda: not os.path.exists(filename), 3)
        if filename and os.path.exists(filename):
            raise Failed("Failed to forget the network")
        # Remove the certificates written beside the profile
        for name in os.listdir(KEYFILES):
            path = os.path.join(KEYFILES, name)
            if name.startswith(uuid + "-") and os.path.isfile(path):
                os.unlink(path)

    def connect(self, req):
        wifi = req["wifi"]
        if req["uuid"] is not None:
            kind, rc = self.profile(req["uuid"])
            dev = self._device_for(kind, req["device"])
            if req["ipv4"] or req["ipv6"]:
                conn = self.NM.SimpleConnection.new_clone(rc)
                self._set_ip(conn, req)
                try:
                    conn.verify()
                except self.GLib.Error:
                    raise Invalid("document") from None
                flags = self.NM.SettingsUpdate2Flags.TO_DISK
                ser = self.NM.ConnectionSerializationFlags.ALL
                self._call(
                    lambda cb: rc.update2(
                        conn.to_dbus(ser), flags, None, None, cb
                    ),
                    rc.update2_finish,
                    "Failed to save the IP settings",
                )
            self._activate(rc, dev)
            return {"uuid": rc.get_uuid(), "state": "connected"}
        if not self.client.wireless_get_enabled():
            raise Failed("Cannot connect: Wi-Fi is off")
        dev = self._device_for("wifi", req["device"])
        for kind, rc in self.profiles():
            sw = rc.get_setting_wireless() if kind == "wifi" else None
            ssid = sw.get_ssid() if sw is not None else None
            if ssid and ssid.get_data() == wifi["ssid"]:
                raise Invalid("wifi.ssid", "already saved, forget it first")
        uuid, conn = self._wifi_connection(wifi, req)
        c = self.client
        # Kept in memory until it connects
        flags = (
            self.NM.SettingsAddConnection2Flags.IN_MEMORY
            | self.NM.SettingsAddConnection2Flags.BLOCK_AUTOCONNECT
        )
        ser = self.NM.ConnectionSerializationFlags.ALL
        rc, _ = self._call(
            lambda cb: c.add_connection2(
                conn.to_dbus(ser), flags, None, False, None, cb
            ),
            c.add_connection2_finish,
            "Failed to save the network",
        )
        try:
            self._activate(rc, dev)
            self._persist(rc, conn)
        except BaseException:
            # Do not keep a network that never connected
            self._delete(rc)
            raise
        finally:
            del conn
        return {"uuid": uuid, "state": "connected"}

    def _persist(self, rc, conn):
        """
        Save a new network that connected, with autoconnect
        """
        NM = self.NM
        conn.get_setting_connection().set_property(
            NM.SETTING_CONNECTION_AUTOCONNECT, True
        )
        ser = NM.ConnectionSerializationFlags.ALL
        self._call(
            lambda cb: rc.update2(
                conn.to_dbus(ser),
                NM.SettingsUpdate2Flags.TO_DISK,
                None,
                None,
                cb,
            ),
            rc.update2_finish,
            "Failed to save the network",
        )

    def disconnect(self, req):
        dev = None
        for _, d in self.devices():
            if d.get_iface() == req["device"]:
                dev = d
        if dev is None:
            raise Invalid("device", "no such device")
        if dev.get_active_connection() is None:
            return {"state": self._state(dev)}
        self._call(
            lambda cb: dev.disconnect_async(None, cb),
            dev.disconnect_finish,
            "Failed to disconnect",
        )
        S = self.NM.DeviceState
        self._spin(lambda: dev.get_state() != S.DEACTIVATING, 5)
        return {"state": self._state(dev)}

    def forget(self, req):
        _, rc = self.profile(req["uuid"], kinds=("wifi",))
        self._delete(rc)
        return {"uuid": req["uuid"]}

    def radio(self, req):
        NM, GLib = self.NM, self.GLib
        if not self.devices("wifi"):
            raise Failed("No Wi-Fi device")
        enabled = req["enabled"]
        c = self.client
        self._call(
            lambda cb: c.dbus_set_property(
                NM.DBUS_PATH,
                NM.DBUS_INTERFACE,
                "WirelessEnabled",
                GLib.Variant("b", enabled),
                5000,
                None,
                cb,
            ),
            c.dbus_set_property_finish,
            "Failed to switch the Wi-Fi",
        )
        self._spin(lambda: c.wireless_get_enabled() == enabled, 3)
        return {"radio": self._radio()}


def reply(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=True) + "\n")
    sys.stdout.flush()


def log(verb, text):
    remote = os.environ.get("QREXEC_REMOTE_DOMAIN", "")
    if not DOMAIN_RE.fullmatch(remote):
        remote = "?"
    syslog.openlog("qubes-net-widget", 0, syslog.LOG_DAEMON)
    syslog.syslog(syslog.LOG_INFO, f"{verb} from {remote}: {text}")


def harden():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(4, 0, 0, 0, 0)  # PR_SET_DUMPABLE
    os.umask(0o077)
    null = os.open(os.devnull, os.O_WRONLY)
    os.dup2(null, 2)
    os.close(null)


def read_input(fd=0, timeout=INPUT_TIMEOUT):
    chunks = []
    size = 0
    end = time.monotonic() + timeout
    while True:
        left = end - time.monotonic()
        if left <= 0 or not select.select([fd], [], [], left)[0]:
            raise Invalid("document", "not sent in time")
        chunk = os.read(fd, 65536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > MAX_INPUT:
            raise Invalid("document", "too large")
        chunks.append(chunk)


def take_slot():
    """
    A free slot of the running services, or None
    """
    for i in range(SLOTS):
        fd = os.open(SLOT.format(i), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            os.close(fd)
    return None


def take_lock():
    fd = os.open(LOCK, os.O_RDWR | os.O_CREAT, 0o600)
    end = time.monotonic() + LOCK_TIMEOUT
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return fd
        except BlockingIOError:
            if time.monotonic() > end:
                os.close(fd)
                raise Failed(
                    "Cannot change the network now: try again"
                ) from None
            time.sleep(0.2)


def main():
    verb = sys.argv[1] if len(sys.argv) == 2 else ""

    def excepthook(*_):
        log(verb or "?", "Failed to run the request")
        reply({"ok": False, "error": "Failed to run the request"})
        os._exit(1)

    def alarm(*_):
        # End the process if cleanup hangs
        signal.signal(signal.SIGALRM, lambda *_: os._exit(1))
        signal.alarm(10)
        raise Failed("Failed to answer in time")

    sys.excepthook = excepthook
    harden()
    signal.signal(signal.SIGALRM, alarm)
    try:
        if verb not in VERBS:
            raise Invalid("service")
        if os.environ.get("QREXEC_SERVICE_ARGUMENT"):
            raise Invalid("service", "takes no argument")
        req = validate(verb, parse(read_input()))
    except Invalid as e:
        log(verb or "?", str(e))
        reply({"ok": False, "error": str(e)})
        return 1
    held = []
    try:
        slot = take_slot()
        if slot is None:
            raise Failed("Cannot answer now: too many calls")
        held.append(slot)
        if verb not in ("status", "scan"):
            held.append(take_lock())
        signal.alarm(TIMEOUT)
        result = getattr(Network(), verb)(req)
    except (Invalid, Failed) as e:
        log(verb, str(e))
        reply({"ok": False, "error": str(e)})
        return 1
    finally:
        signal.alarm(0)
        for fd in held:
            os.close(fd)
    if verb not in ("status", "scan"):
        uuid = result.get("uuid")
        what = f"uuid '{uuid}'" if uuid else f"device '{req.get('device')}'"
        log(verb, f"OK, {what}" if uuid or req.get("device") else "OK")
    reply({"ok": True, **result})
    return 0


if __name__ == "__main__":
    sys.exit(main())
