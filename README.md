# Qubes Network Widget

A tray widget for Ethernet and Wi-Fi of the network qube, in dom0 or a GUI domain, and the qrexec services it calls in the network qube.
It shows each device and the connection carrying the traffic, joins open, WPA2 and WPA3 Personal and hidden Wi-Fi networks, edits IP settings, forgets networks and switches the radio.
The network qube's `nm-applet` is no longer needed: hide it with `Hidden=true` in its `~/.config/autostart/00-qubes-show-hide-nm-applet.desktop`.

## Packages

| Package | Install in | Content |
|---|---|---|
| `qubes-net-widget-dom0` | dom0 | the widget, `/etc/qubes/net-widget.conf` and the default deny policy |
| `qubes-net-widget-netvm` | the network qube's template | the six services and a NetworkManager hook that drops NAT flows of a lost address |
| `qubes-net-widget-guivm` | the GUI domains' template | the widget |

The network qube must be an AppVM, so that it keeps its saved networks.
Other qubes of its template get the services too, closed by the policy.
A template of its own keeps them out.

## Services

| Service | Input | Effect |
|---|---|---|
| `qubes.NetStatus` | `{}` | devices, saved profiles, radio |
| `qubes.NetScan` | `{"rescan": bool}` | Wi-Fi networks in range |
| `qubes.NetConnect` | a new network, or a saved profile's UUID | create or activate a profile, optionally with new IP settings |
| `qubes.NetDisconnect` | `{"device": name}` | disconnect a device |
| `qubes.NetForget` | `{"uuid": uuid}` | delete a saved Wi-Fi profile |
| `qubes.NetRadio` | `{"enabled": bool}` | Wi-Fi radio on or off |

Each answers one JSON document with `ok`, and either the result or a fixed error message.

## Security model

The network qube faces the radio and is untrusted, and the services trust none of their callers.

- A request is one strict JSON document of at most 64 KiB, sent within 10 seconds, with an exact key set per service, validated entirely before NetworkManager is called.
  A qrexec argument is refused.
- Secrets reach NetworkManager over D-Bus through libnm, never through argv, the environment or a file, and no answer carries them.
- Errors name the field, never its value.
- Only Ethernet and Wi-Fi devices and client profiles managed by NetworkManager are touched, never the Qubes `vif` interfaces or uplink profile, hotspots, VPN or WireGuard, and addresses in the Qubes ranges are refused.
- Only open, WPA2 and WPA3 Personal networks are added, an open one after explicit consent.
  A new network stays in memory, without autoconnect, until it connects.
- The services run as root through `force-user='root'`, at most eight at once and the changing ones one at a time, dumping no core.
  Each change logs one line.
- The widget reads at most 256 KiB under a timeout and checks the answer against a strict schema.
  It shows no Pango markup and escapes backslashes and control characters, and in dom0 everything but printable ASCII, so two names never look the same.
  It says when a text comes from the network qube.
- Passwords are cleared after sending, and the widget stores nothing and dumps no core.

A GUI domain allowed to call the services chooses the network, and so the DNS, of every qube behind the network qube, and sees every saved network's name.
Allow only the people who may manage the network.

## Permission model

Allow a GUI domain, for each service, in a policy file read before `90-net-widget.policy`:

```
qubes.NetStatus + sys-gui-alice @default allow target=sys-net autostart=no
```

`+` refuses an argument, `@default` refuses a call naming the network qube, and `autostart=no` never starts it.
Allow GUI domains only, never the qubes they display.
In a GUI domain the widget starts only with `qvm-service sys-gui-alice qubes-net-widget on`.

dom0 calls the services without policy.
There, `/etc/qubes/net-widget.conf` names the network qube and the users who get the widget.
It is a convenience, not a barrier: any dom0 user in group `qubes` can call `qrexec-client`.

## License

GPL-2.0-or-later, see LICENSE.
