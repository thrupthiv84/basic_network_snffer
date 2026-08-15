# basic_network_sniffer

A small Scapy-based network sniffer (sniffer.py) for live packet capture and reading PCAP files.

Requirements

- Python 3.8+
- scapy (install with: pip install scapy)
- On Windows: Npcap and run as Administrator

Usage examples

- Live capture and write to pcap:
  python sniffer.py --iface eth0 --count 10 --outfile capture.pcap

- Read packets from an existing pcap:
  python sniffer.py --read capture.pcap

- Apply a BPF filter (e.g., capture HTTP traffic):
  python sniffer.py --iface eth0 --filter "tcp and port 80"

Notes

- Running live capture requires root/Administrator privileges.
- See sniffer.py for implementation details and additional options.
