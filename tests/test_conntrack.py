#!/usr/bin/python3 -I
"""
NAT flows the NetworkManager hook drops
"""

import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

HOOK = Path(__file__).resolve().parent.parent / "src/qubes-net-conntrack"

IP = """#!/bin/sh
case "$1" in
-4) cat <<EOF
1: lo    inet 127.0.0.1/8 scope host lo
2: wls6    inet 192.168.1.20/24 brd 192.168.1.255 scope global wls6
5: vif3.0    inet 10.137.0.5/32 scope global vif3.0
EOF
;;
-6) cat <<EOF
2: wls6    inet6 2001:db8::20/64 scope global
EOF
;;
esac
"""

FLOWS4 = """\
tcp 6 431999 ESTABLISHED src=10.137.0.6 dst=93.184.216.34 sport=40000 \
dport=443 src=93.184.216.34 dst=192.168.0.50 sport=443 dport=40000 mark=0 use=1
udp 17 29 src=10.137.0.6 dst=9.9.9.9 sport=50000 dport=51820 src=9.9.9.9 \
dst=192.168.0.50 sport=51820 dport=50000 mark=0 use=1
tcp 6 431999 ESTABLISHED src=10.137.0.6 dst=1.1.1.1 sport=40001 dport=443 \
src=1.1.1.1 dst=192.168.1.20 sport=443 dport=40001 mark=0 use=1
"""

FLOWS6 = """\
tcp 6 431999 ESTABLISHED src=fd09:24ef:4179::a89:6 dst=2001:db8:1::1 \
sport=40002 dport=443 src=2001:db8:1::1 dst=2001:db8::99 sport=443 \
dport=40002 mark=0 use=1
"""

CONNTRACK = """#!/bin/sh
echo "$@" >> "$LOG/conntrack"
[ -e "$LOG/fail" ] && exit 1
case "$*" in
"-L --src-nat -f ipv4") cat "$LOG/flows4" ;;
"-L --src-nat -f ipv6") cat "$LOG/flows6" ;;
esac
exit 0
"""

LOGGER = """#!/bin/sh
echo "$@" >> "$LOG/logger"
"""


class Hook(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.dir)
        bin_dir = self.dir / "bin"
        bin_dir.mkdir()
        for name, text in (
            ("ip", IP),
            ("conntrack", CONNTRACK),
            ("logger", LOGGER),
        ):
            path = bin_dir / name
            path.write_text(text)
            path.chmod(0o755)
        (self.dir / "flows4").write_text(FLOWS4)
        (self.dir / "flows6").write_text(FLOWS6)
        self.env = dict(
            os.environ,
            PATH=f"{bin_dir}:{os.environ.get('PATH', '/usr/bin:/bin')}",
            LOG=str(self.dir),
        )

    def run_hook(self, *args):
        p = subprocess.run(
            ["bash", str(HOOK), *args],
            env=self.env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(p.returncode, 0, p.stderr)

    def lines(self, name):
        path = self.dir / name
        return path.read_text().splitlines() if path.exists() else []

    def test_drops_flows_of_lost_addresses(self):
        self.run_hook("wls6", "up")
        deleted = [c for c in self.lines("conntrack") if c.startswith("-D")]
        self.assertEqual(
            deleted,
            [
                "-D --src-nat -f ipv4 --reply-dst 192.168.0.50",
                "-D --src-nat -f ipv6 --reply-dst 2001:db8::99",
            ],
        )
        self.assertEqual(
            self.lines("logger"),
            [
                "-t qubes-net-widget Dropped flows NATed to '192.168.0.50',"
                " on wls6 up",
                "-t qubes-net-widget Dropped flows NATed to '2001:db8::99',"
                " on wls6 up",
            ],
        )

    def test_actions(self):
        for action in ("down", "dhcp4-change", "dhcp6-change"):
            self.run_hook("wls6", action)
        self.assertEqual(
            len([c for c in self.lines("conntrack") if c.startswith("-D")]),
            6,
        )
        (self.dir / "conntrack").unlink()
        for action in ("pre-up", "hostname", "connectivity-change", ""):
            self.run_hook("wls6", action)
        self.assertEqual(self.lines("conntrack"), [])

    def test_conntrack_fails(self):
        (self.dir / "fail").touch()
        self.run_hook("wls6", "up")
        self.assertEqual(
            self.lines("logger"),
            [
                "-t qubes-net-widget Failed to read the NAT flows, on wls6 up",
                "-t qubes-net-widget Failed to read the NAT flows, on wls6 up",
            ],
        )
        self.assertFalse(
            [c for c in self.lines("conntrack") if c.startswith("-D")]
        )


if __name__ == "__main__":
    unittest.main()
