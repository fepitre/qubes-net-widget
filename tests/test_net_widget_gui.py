#!/usr/bin/python3 -I
"""
Menus, dialogs and calls of the widget
"""

# pylint: disable=protected-access

import os
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from fixtures import (
    HOME,
    REFUSED,
    TRAVEL,
    WIRED,
    MockTransport,
    ethernet,
    load_widget,
    scan,
    status,
    wifi,
)

try:
    widget = load_widget()
    Gtk = widget.Gtk
    DISPLAY = widget.Gdk.Screen.get_default() is not None
except (ImportError, ValueError):
    widget = None
    DISPLAY = False


def settle(seconds=0.05):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.005)


def texts(item):
    child = item.get_child()
    if isinstance(child, Gtk.Label):
        return [child.get_text()]
    return [
        w.get_text() for w in child.get_children() if isinstance(w, Gtk.Label)
    ]


def rows(menu):
    out = []
    for item in menu.get_children():
        if isinstance(item, Gtk.SeparatorMenuItem):
            out.append("-")
        elif isinstance(item, Gtk.CheckMenuItem):
            out.append(
                ("check", item.get_label(), item.get_active())
                + (item.get_sensitive(),)
            )
        else:
            out.append(" | ".join(texts(item)))
    return out


def entries(item):
    return [(c.get_label(), c.get_sensitive()) for c in item.get_submenu()]


@unittest.skipUnless(DISPLAY, "no display for GTK 3")
class Widget(unittest.TestCase):
    def setUp(self):
        widget.ASCII_ONLY = False
        self.app = widget.NetWidget(MockTransport(False))
        self.app.menu = Gtk.Menu()
        self.app.icon = Gtk.StatusIcon()
        self.calls = []
        self.answer = (None, None)
        self.app.call = self.call

    def tearDown(self):
        for w in Gtk.Window.list_toplevels():
            if isinstance(w, Gtk.Dialog):
                w.destroy()
        self.app.menu.destroy()
        settle()

    def call(self, service, doc, done):
        self.calls.append((service, doc))
        if service not in ("qubes.NetStatus", "qubes.NetScan"):
            done(*self.answer)

    def actions(self):
        return [
            c
            for c in self.calls
            if c[0] not in ("qubes.NetStatus", "qubes.NetScan")
        ]

    def show(self, status_doc, scan_doc=None, error=None):
        self.app.status = None
        if status_doc is not None:
            self.app.status = widget.clean_status(status_doc)
        self.app.scan = widget.clean_scan(scan_doc) if scan_doc else None
        self.app.error = error
        self.app.rebuild()
        return rows(self.app.menu)

    def item(self, text):
        for item in self.app.menu.get_children():
            if not isinstance(item, (Gtk.SeparatorMenuItem, Gtk.CheckMenuItem)):
                if texts(item)[0] == text:
                    return item
        raise KeyError(text)

    def dialogs(self, kind=None):
        return [
            w
            for w in Gtk.Window.list_toplevels()
            if isinstance(w, kind or Gtk.Dialog) and w.get_visible()
        ]


class Menu(Widget):
    def test_waiting(self):
        self.assertEqual(
            self.show(None),
            [
                "Network, from network qube",
                "Waiting for the network qube",
            ],
        )

    def test_refused(self):
        self.assertEqual(self.show(None, error=REFUSED)[1], REFUSED)
        label = self.app.menu.get_children()[1].get_child().get_children()[0]
        self.assertTrue(label.get_style_context().has_class("net-error"))

    def test_dom0_title(self):
        self.app.transport = MockTransport(True)
        self.assertEqual(self.show(None)[0], "Network, from sys-net")

    def test_ethernet_connected(self):
        shown = self.show(status([ethernet("connected"), wifi()]), scan())
        self.assertEqual(
            shown[:4],
            [
                "Network, from network qube",
                "-",
                "Ethernet ens6: Wired connection 1 | Connected, carries the"
                " traffic",
                "-",
            ],
        )
        self.assertEqual(
            entries(self.item("Ethernet ens6: Wired connection 1")),
            [
                ("Disconnect", True),
                ("IP settings of Wired connection 1...", True),
                ("Address 192.168.10.20/24", False),
            ],
        )

    def test_addresses(self):
        doc = status([ethernet("connected"), wifi()])
        doc["devices"][0]["ipv6"]["addresses"] = ["2001:db8::20/64"]
        self.show(doc)
        self.assertEqual(
            entries(self.item("Ethernet ens6: Wired connection 1"))[-1],
            ("Addresses 192.168.10.20/24, 2001:db8::20/64", False),
        )

    def test_no_markup(self):
        doc = status([ethernet("connected"), wifi()])
        doc["profiles"][0]["name"] = "<b>x</b> &amp;"
        self.show(doc)
        item = self.item("Ethernet ens6: <b>x</b> &amp;")
        label = [
            c
            for c in item.get_child().get_children()
            if isinstance(c, Gtk.Label)
        ][0]
        self.assertFalse(label.get_use_markup())
        self.assertEqual(label.get_label(), "Ethernet ens6: <b>x</b> &amp;")
        sub = item.get_submenu().get_children()[1]
        self.assertFalse(sub.get_child().get_use_markup())

    def test_many_profiles(self):
        doc = status([ethernet("connected"), wifi()])
        doc["profiles"] += [
            dict(
                doc["profiles"][2], uuid=f"{i:08x}-0000-4000-8000-000000000000"
            )
            for i in range(200)
        ]
        self.show(doc)
        self.assertEqual(len(self.app.status["profiles"]), 128)

    def test_ethernet_without_cable(self):
        shown = self.show(status([ethernet("unavailable"), wifi()]))
        self.assertIn("Ethernet ens6 | No cable", shown)
        self.assertEqual(
            entries(self.item("Ethernet ens6")),
            [
                ("Connect Wired connection 1", True),
                ("IP settings of Wired connection 1...", True),
            ],
        )

    def test_ethernet_connected_not_default(self):
        shown = self.show(
            status([ethernet("connected", default=False), wifi()])
        )
        self.assertIn(
            "Ethernet ens6: Wired connection 1 | Connected, carries the"
            " traffic",
            shown,
        )

    def test_no_ethernet(self):
        self.assertIn("Ethernet: no device", self.show(status([wifi()])))

    def test_wifi_list(self):
        shown = self.show(
            status([ethernet("unavailable"), wifi(HOME, b"Home", 78)]),
            scan(home_active=True),
        )
        self.assertEqual(
            shown[4:],
            [
                ("check", "Wi-Fi", True, True),
                "Home | connected, saved, WPA3 Personal",
                "Office | WPA2 Enterprise",
                "Guest",
                "Cafe | WPA2/WPA3 Personal",
                "Old router | WEP, unsupported",
                "Travel | saved, not in range, WPA2 Personal",
                "Hidden network...",
            ],
        )
        self.assertFalse(self.item("Old router").get_sensitive())
        self.assertFalse(self.item("Office").get_sensitive())
        self.assertIsNone(self.item("Office").get_submenu())
        self.assertEqual(
            entries(self.item("Home")),
            [
                ("Disconnect", True),
                ("IP settings...", True),
                ("Forget...", True),
            ],
        )
        self.assertEqual(
            entries(self.item("Travel")),
            [("Connect", True), ("IP settings...", True), ("Forget...", True)],
        )

    def test_saved_in_range(self):
        self.show(status([ethernet("connected"), wifi()]), scan())
        self.assertEqual(
            entries(self.item("Home")),
            [("Connect", True), ("IP settings...", True), ("Forget...", True)],
        )

    def test_wifi_off(self):
        shown = self.show(
            status([ethernet("connected"), wifi()], enabled=False)
        )
        self.assertEqual(shown[-1], ("check", "Wi-Fi", False, True))

    def test_wifi_switch_off(self):
        shown = self.show(
            status([ethernet("connected"), wifi()], hardware=False)
        )
        self.assertEqual(
            shown[-2:],
            [("check", "Wi-Fi", True, False), "Wi-Fi is off by its switch"],
        )

    def test_no_wifi_device(self):
        shown = self.show(status([ethernet("connected")], radios=0))
        self.assertEqual(shown[-1], "Wi-Fi: no device")

    def test_scanning(self):
        self.app.scanning = True
        shown = self.show(status([ethernet("disconnected"), wifi()]))
        self.assertIn("Scanning...", shown)

    def test_names_escaped_in_dom0(self):
        widget.ASCII_ONLY = True
        self.app.transport = MockTransport(True)
        doc = scan()
        doc["networks"][0]["ssid_hex"] = "caf\u00e9".encode().hex()
        shown = self.show(status([ethernet("connected"), wifi()]), doc)
        self.assertIn("caf\\xe9 | WPA3 Personal", shown)


class Actions(Widget):
    def activate(self, item, label):
        for child in item.get_submenu():
            if child.get_label() == label:
                child.activate()
                return
        raise KeyError(label)

    def test_disconnect_ethernet(self):
        self.show(status([ethernet("connected"), wifi()]))
        self.activate(
            self.item("Ethernet ens6: Wired connection 1"), "Disconnect"
        )
        self.assertEqual(
            self.actions(), [("qubes.NetDisconnect", {"device": "ens6"})]
        )
        self.assertIn(("qubes.NetScan", {"rescan": True}), self.calls)

    def test_connect_ethernet(self):
        self.show(status([ethernet("unavailable"), wifi()]))
        self.activate(self.item("Ethernet ens6"), "Connect Wired connection 1")
        self.assertEqual(
            self.actions(),
            [("qubes.NetConnect", {"uuid": WIRED, "device": "ens6"})],
        )

    def test_connect_saved_wifi(self):
        self.show(status([ethernet("connected"), wifi()]), scan())
        self.activate(self.item("Home"), "Connect")
        self.assertEqual(self.actions(), [("qubes.NetConnect", {"uuid": HOME})])

    def test_disconnect_wifi(self):
        self.show(
            status([ethernet("unavailable"), wifi(HOME, b"Home", 78)]),
            scan(home_active=True),
        )
        self.activate(self.item("Home"), "Disconnect")
        self.assertEqual(
            self.actions(), [("qubes.NetDisconnect", {"device": "wls6"})]
        )

    def test_radio(self):
        self.show(status([ethernet("connected"), wifi()]))
        (switch,) = [
            c
            for c in self.app.menu.get_children()
            if isinstance(c, Gtk.CheckMenuItem)
        ]
        switch.set_active(False)
        self.assertEqual(
            self.actions(), [("qubes.NetRadio", {"enabled": False})]
        )

    def test_forget(self):
        self.show(status([ethernet("connected"), wifi()]), scan())
        for response, calls in (
            (Gtk.ResponseType.CANCEL, []),
            (Gtk.ResponseType.OK, [("qubes.NetForget", {"uuid": TRAVEL})]),
        ):
            self.activate(self.item("Travel"), "Forget...")
            (ask,) = self.dialogs(Gtk.MessageDialog)
            self.assertEqual(ask.get_property("text"), "Forget Travel?")
            ask.response(response)
            settle()
            self.assertEqual(self.actions(), calls)
            self.assertEqual(self.dialogs(Gtk.MessageDialog), [])

    def test_error_reported(self):
        self.show(status([ethernet("connected"), wifi()]))
        self.answer = (None, widget.CallError("Failed to <i>%s</i> stop"))
        self.activate(
            self.item("Ethernet ens6: Wired connection 1"), "Disconnect"
        )
        (msg,) = self.dialogs(Gtk.MessageDialog)
        self.assertEqual(
            msg.get_property("secondary-text"), "Failed to <i>%s</i> stop"
        )
        self.assertFalse(msg.get_property("secondary-use-markup"))
        msg.response(Gtk.ResponseType.CLOSE)
        settle()
        self.assertEqual(self.dialogs(Gtk.MessageDialog), [])

    def test_open_dialogs(self):
        self.show(status([ethernet("connected"), wifi()]), scan())
        self.item("Guest").activate()
        self.item("Hidden network...").activate()
        self.activate(self.item("Home"), "IP settings...")
        self.activate(
            self.item("Ethernet ens6: Wired connection 1"),
            "IP settings of Wired connection 1...",
        )
        titles = sorted(d.get_title() for d in self.app.dialogs)
        self.assertEqual(
            titles,
            [
                "Connect to Guest",
                "Connect to a hidden network",
                "IP settings of Home",
                "IP settings of Wired connection 1",
            ],
        )
        for d in list(self.app.dialogs):
            d.destroy()
        self.assertEqual(self.app.dialogs, [])


class Icon(Widget):
    def icon(self):
        path = self.app.icon.get_gicon().get_file().get_path()
        return os.path.basename(path), self.app.icon.get_tooltip_text()

    def got(self, doc, error=None):
        self.app.got_status(doc, error)
        return self.icon()

    def test_states(self):
        self.assertEqual(
            self.got(status([ethernet("connected"), wifi()])),
            ("qubes-net-wired.svg", "Ethernet ens6: Wired connection 1"),
        )
        self.assertEqual(
            self.got(
                status([ethernet("unavailable"), wifi(HOME, b"Home", 60)])
            ),
            ("qubes-net-wifi-3.svg", "Wi-Fi: Home, 60%"),
        )
        self.assertEqual(
            self.got(status([ethernet("unavailable"), wifi()])),
            ("qubes-net-offline.svg", "Network: not connected"),
        )
        self.assertEqual(
            self.got(None, widget.CallError(REFUSED)),
            ("qubes-net-error.svg", REFUSED),
        )
        self.assertEqual(
            self.got({"radio": 1}),
            ("qubes-net-error.svg", "Invalid answer from the network qube"),
        )

    def test_bars(self):
        self.assertEqual(
            [widget.bars(s) for s in (0, 4, 5, 24, 25, 50, 75, 99, 100)],
            [0, 0, 1, 1, 2, 3, 4, 4, 4],
        )

    def test_unknown_profile(self):
        self.app.got_status(status([ethernet("connected"), wifi()]), None)
        self.assertEqual(self.app.profile_name(TRAVEL), "Travel")
        self.assertEqual(
            self.app.profile_name("00000000-0000-0000-0000-000000000000"),
            "unknown connection",
        )

    def test_scan(self):
        self.app.got_scan(scan(), None)
        self.assertEqual(len(self.app.scan["networks"]), 5)
        self.app.got_scan({"networks": "x"}, None)
        self.assertIsNone(self.app.scan)
        self.app.got_scan(scan(), None)
        self.app.got_scan(None, widget.CallError("Failed"))
        self.assertEqual(len(self.app.scan["networks"]), 5)

    def test_poll(self):
        self.assertTrue(self.app.poll())
        self.assertEqual(self.calls, [("qubes.NetStatus", {})])
        self.calls.clear()
        self.app.polling = False
        self.app.got_status(status([ethernet("connected"), wifi()]), None)
        self.app.poll()
        self.assertEqual(
            self.calls,
            [("qubes.NetStatus", {}), ("qubes.NetScan", {"rescan": False})],
        )

    def test_changed_while_shown(self):
        shown = []
        self.app.show_menu = shown.append
        self.app.changed()
        self.assertEqual(shown, [])
        self.app.popup(None)
        self.assertEqual(shown, [None])
        anchor = Gtk.Window(type=Gtk.WindowType.POPUP)
        anchor.show()
        self.app.menu.popup_at_widget(
            anchor, widget.Gdk.Gravity.SOUTH, widget.Gdk.Gravity.NORTH, None
        )
        settle(0.2)
        self.app.got_status(status([ethernet("connected"), wifi()]), None)
        self.assertEqual(shown, [None, None])
        self.assertIn(
            "Ethernet ens6: Wired connection 1 | Connected, carries the"
            " traffic",
            rows(self.app.menu),
        )
        anchor.destroy()


class Dialogs(Widget):
    def setUp(self):
        super().setUp()
        self.show(status([ethernet("connected"), wifi()]), scan())
        self.networks = {n["ssid"]: n for n in self.app.scan["networks"]}

    def wifi(self, ssid=None):
        d = widget.WifiDialog(self.app, self.networks[ssid] if ssid else None)
        self.app.open_dialog(d)
        return d

    def send(self, dialog):
        dialog.response(Gtk.ResponseType.OK)
        return self.actions()

    def test_personal(self):
        d = self.wifi(b"Cafe")
        self.assertTrue(d.personal.get_visible())
        self.assertEqual(self.send(d), [])
        self.assertEqual(d.error.get_text(), "No password")
        d.psk.set_text("correct horse")
        self.answer = (None, widget.CallError("Failed to connect"))
        (call,) = self.send(d)
        self.assertEqual(
            call,
            (
                "qubes.NetConnect",
                {
                    "wifi": {
                        "security": "wpa3-psk",
                        "ssid_hex": b"Cafe".hex(),
                        "psk": "correct horse",
                    }
                },
            ),
        )
        self.assertEqual(d.psk.get_text(), "")
        self.assertEqual(d.error.get_text(), "Failed to connect")
        self.assertTrue(d.ok.get_sensitive())

    def test_transition_hex_key(self):
        d = self.wifi(b"Cafe")
        d.psk.set_text("ab" * 32)
        (call,) = self.send(d)
        self.assertEqual(call[1]["wifi"]["security"], "wpa2-psk")

    def test_open(self):
        d = self.wifi(b"Guest")
        self.assertTrue(d.open_box.get_visible())
        self.assertEqual(self.send(d), [])
        self.assertEqual(
            d.error.get_text(),
            "Cannot connect: tick 'I understand, connect anyway'",
        )
        d.accept_open.set_active(True)
        (call,) = self.send(d)
        self.assertEqual(
            call[1],
            {
                "wifi": {
                    "security": "open",
                    "ssid_hex": b"Guest".hex(),
                    "accept_open": True,
                }
            },
        )

    def test_hidden(self):
        d = self.wifi()
        d.psk.set_text("secret")
        self.send(d)
        self.assertEqual(
            d.error.get_text(), "Invalid network name: 1 to 32 bytes"
        )
        d.ssid.set_text("Lab")
        d.security.set_active_id("wpa2-psk")
        d.ipv4.method.set_active_id("manual")
        d.ipv4.addresses.set_text("192.168.5.2/24")
        (call,) = self.send(d)
        self.assertEqual(
            call[1],
            {
                "wifi": {
                    "security": "wpa2-psk",
                    "ssid": "Lab",
                    "hidden": True,
                    "psk": "secret",
                },
                "ipv4": {"method": "manual", "addresses": ["192.168.5.2/24"]},
            },
        )

    def test_cancel(self):
        d = self.wifi(b"Cafe")
        d.psk.set_text("secret")
        d.response(Gtk.ResponseType.CANCEL)
        settle()
        self.assertEqual(self.app.dialogs, [])
        self.assertEqual(self.actions(), [])
        self.assertEqual(d.psk.get_text(), "")

    def test_ip_settings(self):
        d = widget.IPDialog(self.app, self.app.profile(WIRED))
        self.app.open_dialog(d)
        f4 = d.ipv4
        self.assertFalse(f4.addresses.get_visible())
        self.assertTrue(f4.dns.get_visible())
        f4.method.set_active_id("manual")
        self.assertTrue(f4.addresses.get_visible())
        self.send(d)
        self.assertEqual(d.error.get_text(), "Invalid IPv4 address: give one")
        f4.addresses.set_text("192.168.10.30")
        self.send(d)
        self.assertEqual(
            d.error.get_text(), "Invalid IPv4 address: add the prefix, as /24"
        )
        f4.addresses.set_text("192.168.10.30/24, 192.168.10.31/24")
        f4.gateway.set_text(" 192.168.10.1 ")
        f4.dns.set_text("192.168.10.1; 9.9.9.9")
        f4.search.set_text("Lab.Example")
        d.ipv6.method.set_active_id("disabled")
        self.assertFalse(d.ipv6.dns.get_visible())
        (call,) = self.send(d)
        self.assertEqual(
            call,
            (
                "qubes.NetConnect",
                {
                    "uuid": WIRED,
                    "ipv4": {
                        "method": "manual",
                        "addresses": ["192.168.10.30/24", "192.168.10.31/24"],
                        "gateway": "192.168.10.1",
                        "dns": ["192.168.10.1", "9.9.9.9"],
                        "search": ["lab.example"],
                    },
                    "ipv6": {"method": "disabled"},
                },
            ),
        )

    def test_ip_form_current(self):
        current = {
            "method": "manual",
            "addresses": ["2001:db8::2/64"],
            "gateway": "2001:db8::1",
            "dns": [],
            "search": ["lab.example"],
        }
        form = widget.IPForm(6, current)
        self.assertEqual(
            form.value(),
            {
                "method": "manual",
                "addresses": ["2001:db8::2/64"],
                "gateway": "2001:db8::1",
                "search": ["lab.example"],
            },
        )
        self.assertEqual(
            widget.IPForm(4, {"method": "other"}).value(), {"method": "auto"}
        )


@unittest.skipUnless(DISPLAY, "no display for GTK 3")
class Calls(unittest.TestCase):
    def transport(self, code, dom0=False):
        t = widget.Transport("sys-net" if dom0 else "@default", dom0)
        t.argv = lambda service: [sys.executable, "-I", "-c", code]
        return t

    def answer(self, data, rc=0, err=b""):
        if isinstance(data, str):
            data = data.encode()
        return self.transport(
            "import sys; sys.stdin.read();"
            f" sys.stdout.buffer.write({data!r});"
            f" sys.stderr.buffer.write({err!r}); sys.exit({rc})"
        )

    def refused(self, t):
        with self.assertRaises(widget.CallError) as cm:
            t.call("qubes.NetStatus", {})
        return str(cm.exception)

    def test_argv(self):
        self.assertEqual(
            widget.Transport("sys-net", True).argv("qubes.NetStatus"),
            [
                widget.QREXEC_DOM0,
                "-d",
                "sys-net",
                "DEFAULT:QUBESRPC qubes.NetStatus+ dom0",
            ],
        )
        self.assertEqual(
            widget.Transport("@default", False).argv("qubes.NetScan"),
            [widget.QREXEC_VM, "@default", "qubes.NetScan"],
        )

    def test_round_trip(self):
        t = self.transport(
            "import json, sys; d = json.load(sys.stdin);"
            " print(json.dumps({'ok': True, 'got': d}))"
        )
        doc = {"rescan": True, "name": "caf\u00e9"}
        self.assertEqual(t.call("qubes.NetScan", doc), {"ok": True, "got": doc})

    def test_large_request(self):
        t = self.transport(
            "import json, sys; d = json.load(sys.stdin);"
            " print(json.dumps({'ok': True, 'n': len(d['x'])}))"
        )
        self.assertEqual(
            t.call("qubes.NetConnect", {"x": "a" * 300000})["n"], 300000
        )

    def test_failures(self):
        name = "the network qube"
        cases = [
            (self.answer("", 126), f"Cannot call {name}: refused"),
            (
                self.answer("", 1, b"Request refused\n"),
                f"Cannot call {name}: refused",
            ),
            (self.answer(""), f"Cannot reach {name}"),
            (self.answer("{"), f"Invalid answer from {name}"),
            (
                self.answer('{"ok": true, "ok": true}'),
                f"Invalid answer from {name}",
            ),
            (
                self.answer('{"ok": true, "x": NaN}'),
                f"Invalid answer from {name}",
            ),
            (self.answer("[1]"), f"Invalid answer from {name}"),
            (self.answer('{"ok": 1}'), f"Invalid answer from {name}"),
            (
                self.answer('{"ok": false, "error": 3}'),
                f"Invalid answer from {name}",
            ),
            (self.answer(b"\xff"), f"Invalid answer from {name}"),
            (
                self.answer('{"ok": false, "error": "Failed to\\nconnect"}'),
                "From the network qube: Failed to\\x0aconnect",
            ),
        ]
        for t, message in cases:
            self.assertTrue(self.refused(t).startswith(message), message)

    def test_no_qrexec(self):
        t = widget.Transport("@default", False)
        t.argv = lambda service: ["/nonexistent/qrexec-client-vm"]
        self.assertEqual(self.refused(t), "Cannot run qrexec")

    def test_too_large(self):
        with mock.patch.object(widget, "MAX_ANSWER", 1000):
            t = self.transport("print('x' * 5000)")
            self.assertEqual(self.refused(t), "Invalid answer: too large")

    def test_long_stderr(self):
        t = self.answer('{"ok": true}', 0, b"e" * 10000)
        self.assertEqual(t.call("qubes.NetStatus", {}), {"ok": True})

    def test_timeout(self):
        with mock.patch.object(widget, "TIMEOUT", 0.3):
            t = self.transport("import time; time.sleep(5)")
            self.assertEqual(
                self.refused(t), "No answer in time from the network qube"
            )
            for code in (
                "import os, time; os.close(1); time.sleep(5)",
                "import os, time; os.close(1); os.close(2); time.sleep(5)",
            ):
                t = self.transport(code)
                self.assertEqual(
                    self.refused(t), "No answer in time from the network qube"
                )

    def test_threaded(self):
        app = widget.NetWidget(self.answer('{"ok": true, "x": 1}'))
        results = []
        app.call("qubes.NetStatus", {}, lambda r, e: results.append((r, e)))
        end = time.monotonic() + 10
        while not results and time.monotonic() < end:
            settle()
        self.assertEqual(results, [({"ok": True, "x": 1}, None)])
        bad = widget.Transport("@default", False)
        bad.call = mock.Mock(side_effect=RuntimeError("boom"))
        app = widget.NetWidget(bad)
        results.clear()
        app.call("qubes.NetStatus", {}, lambda r, e: results.append((r, e)))
        while not results and time.monotonic() < end:
            settle()
        self.assertIsNone(results[0][0])
        self.assertEqual(str(results[0][1]), "Failed to call the service")


@unittest.skipUnless(DISPLAY, "no display for GTK 3")
class Storage(unittest.TestCase):
    SECRET = "correct horse battery"

    def test_nothing_stored(self):
        code = f"""
            import sys
            sys.path.insert(0, {str(Path(__file__).resolve().parent)!r})
            from fixtures import MockTransport, ethernet, load_widget
            from fixtures import scan, status, wifi
            w = load_widget()
            app = w.NetWidget(MockTransport(False))
            app.call = lambda service, doc, done: done(None, None)
            app.status = w.clean_status(status([ethernet("connected"), wifi()]))
            app.scan = w.clean_scan(scan())
            nets = {{n["ssid"]: n for n in app.scan["networks"]}}
            d = w.WifiDialog(app, nets[b"Cafe"])
            d.psk.set_text({self.SECRET!r})
            d.response(w.Gtk.ResponseType.OK)
            while w.Gtk.events_pending():
                w.Gtk.main_iteration_do(False)
            print([m for m in sys.modules if "Secret" in m or "keyring" in m])
            """
        code = textwrap.dedent(code)
        with tempfile.TemporaryDirectory() as home:
            env = {
                "HOME": home,
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "DISPLAY": os.environ["DISPLAY"],
                "XAUTHORITY": os.environ.get("XAUTHORITY", ""),
                "XDG_RUNTIME_DIR": home,
            }
            p = subprocess.run(
                [sys.executable, "-I", "-c", code],
                env=env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(p.stdout.strip(), "[]")
            for f in Path(home).rglob("*"):
                if f.is_file():
                    self.assertNotIn(
                        self.SECRET.encode(), f.read_bytes(), str(f)
                    )


@unittest.skipIf(widget is None, "no PyGObject with GTK 3")
class LoadTransport(unittest.TestCase):
    def load(self, files, conf=None, user="alice"):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "net-widget.conf")
            if conf is not None:
                with open(path, "wb") as f:
                    f.write(conf)
            exists = os.path.exists

            def mock_exists(p):
                if p in ("/etc/qubes-release", widget.FLAG):
                    return p in files
                return exists(p)

            pw = mock.Mock(pw_name=user)
            with mock.patch.object(widget, "CONF", path), mock.patch.object(
                widget.os.path, "exists", mock_exists
            ), mock.patch.object(widget.pwd, "getpwuid", return_value=pw):
                return widget.load_transport()

    def test_dom0(self):
        conf = b"# who\nnetqube = sys-net\nusers = admin alice\n"
        t = self.load(["/etc/qubes-release"], conf)
        self.assertEqual(
            (t.target, t.dom0, t.name), ("sys-net", True, "sys-net")
        )
        self.assertIsNone(self.load(["/etc/qubes-release"], conf, "bob"))
        for bad in (
            b"netqube=dom0\nusers=alice\n",
            b"netqube=-x\nusers=alice\n",
        ):
            self.assertIsNone(self.load(["/etc/qubes-release"], bad))
        self.assertIsNone(self.load(["/etc/qubes-release"], b"\xff"))
        self.assertIsNone(self.load(["/etc/qubes-release"]))

    def test_gui_domain(self):
        t = self.load([widget.FLAG])
        self.assertEqual((t.target, t.dom0), ("@default", False))
        self.assertIsNone(self.load([]))


if __name__ == "__main__":
    unittest.main()
