#!/usr/bin/python3
"""
Screenshots of the widget's menus and dialogs
"""

import argparse
import sys
import time
from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Gdk", "3.0")
gi.require_version("GdkPixbuf", "2.0")
from gi.repository import Gdk, GdkPixbuf, Gtk  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tests"))
from fixtures import (  # noqa: E402
    HOME,
    REFUSED,
    WIRED,
    MockTransport,
    ethernet,
    hostile_scan,
    load_widget,
    scan,
    status,
    wifi,
)

widget = load_widget()


def settle(seconds=0.4):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        while Gtk.events_pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.02)


def frame(window):
    r = window.get_frame_extents()
    return r.x, r.y, r.x + r.width, r.y + r.height


def save(windows, path):
    boxes = [frame(w) for w in windows]
    x0, y0 = min(b[0] for b in boxes), min(b[1] for b in boxes)
    x1, y1 = max(b[2] for b in boxes), max(b[3] for b in boxes)
    root = Gdk.get_default_root_window()
    shot = GdkPixbuf.Pixbuf.new(
        GdkPixbuf.Colorspace.RGB, True, 8, x1 - x0, y1 - y0
    )
    shot.fill(0)
    for bx0, by0, bx1, by1 in boxes:
        part = Gdk.pixbuf_get_from_window(root, bx0, by0, bx1 - bx0, by1 - by0)
        part.add_alpha(False, 0, 0, 0).copy_area(
            0, 0, bx1 - bx0, by1 - by0, shot, bx0 - x0, by0 - y0
        )
    shot.savev(str(path), "png", [], [])
    print(f"{path.name}: {x1 - x0}x{y1 - y0}")


class Screenshots:
    def __init__(self, out):
        self.out = out
        self.suffix = ""
        self.app = widget.NetWidget(MockTransport(False))
        self.app.menu = Gtk.Menu()
        self.app.menu.set_reserve_toggle_size(False)
        widget.load_style(self.app.menu)
        self.anchor = Gtk.Window(type=Gtk.WindowType.POPUP)
        self.anchor.move(16, 16)
        self.anchor.resize(1, 1)
        self.anchor.show()
        settle()

    def answers(self, status_doc, scan_doc=None, dom0=False, error=None):
        widget.ASCII_ONLY = dom0
        self.app.transport = MockTransport(dom0)
        self.app.error = error
        self.app.status = None
        if status_doc is not None:
            self.app.status = widget.clean_status(status_doc)
        self.app.scan = None
        if scan_doc is not None:
            self.app.scan = widget.clean_scan(scan_doc)

    def menu(self, name, submenu=None):
        menu = self.app.menu
        self.app.rebuild()
        rect = Gdk.Rectangle()
        rect.x, rect.y, rect.width, rect.height = 0, 0, 1, 1
        menu.popup_at_rect(
            self.anchor.get_window(),
            rect,
            Gdk.Gravity.SOUTH_WEST,
            Gdk.Gravity.NORTH_WEST,
            None,
        )
        settle()
        windows = [menu.get_toplevel().get_window()]
        if submenu is not None:
            item = [
                c for c in menu.get_children() if c.get_submenu() is not None
            ][submenu]
            menu.select_item(item)
            item.activate()
            settle(0.8)
            windows.append(item.get_submenu().get_toplevel().get_window())
        save(windows, self.out / f"{name}{self.suffix}.png")
        menu.popdown()
        settle(0.2)

    def dialog(self, name, dialog):
        dialog.show()
        settle(0.6)
        save([dialog.get_window()], self.out / f"{name}{self.suffix}.png")
        dialog.destroy()
        settle(0.2)

    def dark(self):
        settings = Gtk.Settings.get_default()
        settings.set_property("gtk-application-prefer-dark-theme", True)
        settle(0.2)
        widget.load_style(self.app.menu)
        self.suffix = "-dark"


def scenes(shots):
    app = shots.app

    shots.answers(status([ethernet("connected"), wifi()]), scan())
    shots.menu("menu-ethernet")
    shots.menu("menu-ethernet-actions", submenu=0)
    shots.answers(
        status([ethernet("unavailable"), wifi(HOME, b"Home", 78)]),
        scan(home_active=True),
    )
    shots.menu("menu-wifi")
    shots.menu("menu-wifi-actions", submenu=1)
    shots.answers(status([ethernet("connected"), wifi()], enabled=False))
    shots.menu("menu-wifi-off")
    shots.answers(status([ethernet("connected"), wifi()], hardware=False))
    shots.menu("menu-wifi-switch-off")
    shots.answers(status([ethernet("disconnected"), wifi()]))
    app.scanning = True
    shots.menu("menu-scanning")
    app.scanning = False
    shots.answers(None, error=REFUSED)
    shots.menu("menu-refused")
    shots.answers(None)
    shots.menu("menu-waiting")
    shots.answers(status([ethernet("connected"), wifi()]), hostile_scan())
    shots.menu("menu-names-gui-domain")
    shots.answers(status([ethernet("connected"), wifi()]), hostile_scan(), True)
    shots.menu("menu-names-dom0")

    shots.answers(status([ethernet("connected"), wifi()]), scan())
    networks = {n["ssid"]: n for n in app.scan["networks"]}
    shots.dialog(
        "dialog-wifi-personal", widget.WifiDialog(app, networks[b"Cafe"])
    )
    shots.dialog("dialog-wifi-open", widget.WifiDialog(app, networks[b"Guest"]))
    shots.dialog("dialog-wifi-hidden", widget.WifiDialog(app))
    shots.dialog("dialog-ip-settings", widget.IPDialog(app, app.profile(WIRED)))


def main():
    parser = argparse.ArgumentParser(description=__doc__.strip())
    parser.add_argument("out", type=Path, help="directory of the images")
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    shots = Screenshots(args.out)
    scenes(shots)
    shots.dark()
    scenes(shots)
    return 0


if __name__ == "__main__":
    sys.exit(main())
