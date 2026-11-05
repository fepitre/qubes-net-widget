"""
Network qube answers for tests and screenshots
"""

import importlib.util
from importlib.machinery import SourceFileLoader
from pathlib import Path

TOP = Path(__file__).resolve().parent.parent

WIRED = "6f1c2a8e-3b5d-4e7f-9a1b-2c3d4e5f6a7b"
HOME = "1b2c3d4e-5f6a-4b8c-9d0e-1f2a3b4c5d6e"
TRAVEL = "2c3d4e5f-6a7b-4c9d-8e1f-2a3b4c5d6e7f"
ARABIC = "\u0634\u0628\u0643\u0629"
REFUSED = (
    "Cannot call the network qube: refused by the dom0 policy or not running"
)


def ip(addresses=(), gateway=None, dns=()):
    return {"addresses": list(addresses), "gateway": gateway, "dns": list(dns)}


def lease(prefix):
    return ip([f"{prefix}.20/24"], f"{prefix}.1", [f"{prefix}.1"])


def ethernet(state, default=True):
    up = state == "connected"
    return {
        "iface": "ens6",
        "type": "ethernet",
        "state": state,
        "profile": WIRED if up else None,
        "default4": up and default,
        "default6": False,
        "ipv4": lease("192.168.10") if up else ip(),
        "ipv6": ip(),
    }


def wifi(profile=None, ssid=b"", signal=0):
    dev = {
        "iface": "wls6",
        "type": "wifi",
        "state": "connected" if profile else "disconnected",
        "profile": profile,
        "default4": profile is not None,
        "default6": False,
        "ipv4": lease("192.168.1") if profile else ip(),
        "ipv6": ip(),
    }
    if profile:
        dev["ap"] = {
            "ssid_hex": ssid.hex(),
            "signal": signal,
            "security": "wpa3-psk",
        }
    return dev


def known(uuid, kind, name, active=None, ssid=None, security=None):
    p = {
        "uuid": uuid,
        "type": kind,
        "name": name,
        "saved": True,
        "active": active,
        "ipv4": {"method": "auto"},
        "ipv6": {"method": "auto"},
    }
    if kind == "wifi":
        p.update(ssid_hex=ssid.hex(), hidden=False, security=security)
    return p


def status(devices, enabled=True, hardware=True, active=None, radios=1):
    profiles = [
        known(WIRED, "ethernet", "Wired connection 1", active=active),
        known(HOME, "wifi", "Home", None, b"Home", "wpa3-psk"),
        known(TRAVEL, "wifi", "Travel", None, b"Travel", "wpa2-psk"),
    ]
    for p in profiles:
        for d in devices:
            if d["profile"] == p["uuid"]:
                p["active"] = d["iface"]
    return {
        "radio": {
            "hardware": hardware,
            "enabled": enabled,
            "devices": radios,
        },
        "devices": devices,
        "profiles": profiles,
        "primary": next((d["profile"] for d in devices if d["profile"]), None),
    }


def network(ssid, signal, security, saved=None, active=False):
    return {
        "ssid_hex": ssid.hex(),
        "signal": signal,
        "security": security,
        "saved": saved,
        "active": active,
    }


def scan(home_active=False):
    return {
        "radio": {"hardware": True, "enabled": True, "devices": 1},
        "networks": [
            network(b"Home", 78, "wpa3-psk", HOME, home_active),
            network(b"Office", 64, "wpa2-eap"),
            network(b"Guest", 51, "open"),
            network(b"Cafe", 33, "wpa3-transition"),
            network(b"Old router", 18, "wep"),
        ],
    }


def hostile_scan():
    names = [
        f"{ARABIC} 5G",
        "caf\u00e9",
        "\U0001f600 hotspot",
        "a\u202egnp.exe",
        "line\nbreak",
    ]
    return {
        "radio": {"hardware": True, "enabled": True, "devices": 1},
        "networks": [
            network(n.encode(), 70 - 10 * i, "wpa2-psk")
            for i, n in enumerate(names)
        ],
    }


class MockTransport:
    """
    Transport that never calls
    """

    def __init__(self, dom0):
        self.dom0 = dom0
        self.target = "sys-net"
        self.name = self.target if dom0 else "the network qube"


def load_widget():
    """
    Load the widget as a module
    """
    loader = SourceFileLoader("netwidget", str(TOP / "src/qubes-net-widget"))
    module = importlib.util.module_from_spec(
        importlib.util.spec_from_loader("netwidget", loader)
    )
    loader.exec_module(module)
    module.ICONS = str(TOP / "icons")
    return module
