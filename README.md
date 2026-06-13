# Snare
Snare is a versatile red teaming tool for wireless network analysis and attacks. It allows you to capture packets, decrypt traffic, execute deauthentication attacks, crack handshakes, launch WPS attacks, and more — all from an interactive menu that requires no memorisation of commands.

## Description

Snare is a powerful red teaming tool designed to assist in wireless network analysis and penetration testing. It was originally created to manually sniff network traffic and identify open ports on routers that prohibit traditional port scans. Snare has since grown into a full-featured WiFi security assessment platform with a user-friendly interactive interface.

**This project is for educational purposes and authorised penetration testing only.** By using Snare you accept full responsibility for ensuring you have explicit permission to test any network you target.

## Features

- **Interactive menu** — no need to memorise commands or MAC addresses
- **Auto interface detection** — lists your wireless adapters automatically
- **Multi-backend scanning** — airodump-ng, hcxdumptool, Kismet (whichever is installed)
- **Multi-backend capture** — Scapy (built-in), hcxdumptool, tshark, tcpdump
- **Packet decryption** — strip wireless headers with airdecap-ng
- **Network data extraction** — MACs, IPs, ports via tshark with a live preview table
- **Deauthentication attacks** — aireplay-ng, mdk4, or bettercap
- **Handshake / hash cracking** — hashcat, john, cowpatty, or aircrack-ng
- **WPS attacks** — reaver + pixiewps Pixie Dust
- **Rogue AP / Evil Twin** — hostapd + dnsmasq setup wizard
- **Automated audit** — launches wifite with one keypress
- **Tool availability dashboard** — shows which optional tools are installed
- **CLI arguments** — supply password, wordlist, interface, channel, and more upfront

## Requirements

### Python Libraries

```
pip install -r requirements.txt
```

Installs: `scapy`, `rich`

### Required External Tools

```bash
sudo apt install aircrack-ng tshark
```

### Optional External Tools (unlock extra features)

| Tool | Feature | Install |
|------|---------|---------|
| hcxdumptool | PMKID / handshake harvesting | `sudo apt install hcxdumptool` |
| hcxtools | Convert captures to hashcat format | `sudo apt install hcxtools` |
| hashcat | GPU-accelerated cracking | `sudo apt install hashcat` |
| john | CPU-based cracking | `sudo apt install john` |
| cowpatty | WPA-PSK offline cracker | `sudo apt install cowpatty` |
| reaver | WPS PIN brute-force | `sudo apt install reaver` |
| pixiewps | WPS Pixie Dust attack | `sudo apt install pixiewps` |
| wash | WPS network scanner | `sudo apt install reaver` |
| mdk4 | Beacon flood / deauth | `sudo apt install mdk4` |
| bettercap | Swiss-army network tool | `sudo apt install bettercap` |
| kismet | Passive wireless detector | `sudo apt install kismet` |
| wifite | Automated WiFi audit | `sudo apt install wifite` |
| hostapd | Rogue AP | `sudo apt install hostapd` |
| dnsmasq | DHCP/DNS for rogue AP | `sudo apt install dnsmasq` |

### System Requirements

- Linux (Kali, Ubuntu, Debian, Parrot, etc.)
- Wireless adapter that supports monitor mode

## Usage

```bash
sudo python3 Snare.py
```

Just run it — Snare will detect your interfaces, ask for confirmation, and drop you into the menu.

### CLI Arguments

All arguments are optional. Snare runs fully interactively without any of them.

```
usage: Snare [-h] [--interface IFACE] [--password PASS] [--ssid SSID]
             [--wordlist FILE] [--channel CH] [--output FILE] [--yes] [--no-monitor]

  -i, --interface  Wireless interface (skip interactive selection)
  -p, --password   WiFi password for decryption (skip the prompt)
  -s, --ssid       Network SSID for decryption (skip the prompt)
  -w, --wordlist   Default wordlist path for cracking
  -c, --channel    Default channel to lock to during capture
  -o, --output     Default output file for captures
  -y, --yes        Skip the authorization confirmation prompt
      --no-monitor Use interface as-is (already in monitor mode)
```

### Examples

```bash
# Fully interactive
sudo python3 Snare.py

# Pre-select interface
sudo python3 Snare.py --interface wlan0

# Supply WiFi password upfront (no prompt during decrypt)
sudo python3 Snare.py --password MyWiFiPassword

# Crack with a custom wordlist
sudo python3 Snare.py --wordlist /usr/share/wordlists/rockyou.txt

# Capture on channel 6 with a preset output file
sudo python3 Snare.py -i wlan0 -c 6 -o capture.pcap

# Skip confirmation (for scripts)
sudo python3 Snare.py --yes
```

## Menu Options

```
1  Scan for nearby networks
2  Capture packets
3  Decrypt captured traffic          (airdecap-ng)
4  Extract network data              (tshark)
5  Deauthentication / disruption
6  Crack handshake / hash
7  WPS attacks                       (reaver / pixiewps)
8  Rogue AP / Evil Twin              (hostapd + dnsmasq)
9  Automated WiFi audit              (wifite)
t  Show tool availability
0  Disable monitor mode & exit
```

## Contributing

Snare is open source. Fork the repository and submit pull requests for improvements. Open an issue for bug reports or feature requests.

---

## License

MIT License

Copyright (c) 2024 Arash Goodarzi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
