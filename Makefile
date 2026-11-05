#
# The Qubes OS Project, http://www.qubes-os.org
#
# Copyright (C) 2026  Frédéric Pierret <frederic@invisiblethingslab.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
#

LIBDIR ?= /usr/lib
PYTHON ?= /usr/bin/python3

SERVICES := qubes.NetStatus qubes.NetScan qubes.NetConnect \
	qubes.NetDisconnect qubes.NetForget qubes.NetRadio

build:

check:
	$(PYTHON) -I -B -c 'import sys; [compile(open(f).read(), f, "exec") \
		for f in sys.argv[1:]]' src/qubes-netsvc.py \
		src/qubes-net-widget
	$(PYTHON) -I -B -m unittest discover -v -s tests

install-netvm:
	install -D -m 0644 src/qubes-netsvc.py \
		$(DESTDIR)$(LIBDIR)/qubes-net-widget/netsvc.py
	install -D -m 0755 src/qubes-net-conntrack \
		$(DESTDIR)/etc/NetworkManager/dispatcher.d/90-qubes-net-conntrack
	install -d $(DESTDIR)/etc/qubes-rpc $(DESTDIR)/etc/qubes/rpc-config
	for svc in $(SERVICES); do \
		install -m 0755 qubes-rpc/$$svc $(DESTDIR)/etc/qubes-rpc/$$svc; \
		echo "force-user='root'" > $(DESTDIR)/etc/qubes/rpc-config/$$svc; \
	done

install-widget:
	install -D -m 0755 src/qubes-net-widget \
		$(DESTDIR)/usr/bin/qubes-net-widget
	install -D -m 0644 autostart/qubes-net-widget.desktop \
		$(DESTDIR)/etc/xdg/autostart/qubes-net-widget.desktop
	install -d $(DESTDIR)/usr/share/qubes-net-widget/icons
	install -m 0644 -t $(DESTDIR)/usr/share/qubes-net-widget/icons \
		icons/*.svg

install-guivm: install-widget

install-vm: install-netvm install-guivm

install-dom0: install-widget
	install -D -m 0644 dom0/net-widget.conf \
		$(DESTDIR)/etc/qubes/net-widget.conf
	install -D -m 0644 policy/90-net-widget.policy \
		$(DESTDIR)/etc/qubes/policy.d/90-net-widget.policy

clean:
	rm -rf pkgs
	find . -name __pycache__ -prune -exec rm -rf {} +

.PHONY: build check install-netvm install-widget install-guivm install-vm \
	install-dom0 clean
