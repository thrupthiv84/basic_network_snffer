#!/usr/bin/env python3

"""
Basic Network Sniffer using scapy.

Usage examples:
  python sniffer.py -i eth0 --count 10
  python sniffer.py -r capture.pcap

Requires: scapy (install via pip)
Run as root/Administrator for live capture. On Windows install Npcap and run as admin.
"""

import argparse
import binascii
import sys

from scapy.all import sniff, rdpcap, PcapWriter, raw
from scapy.layers.inet import IP, TCP, UDP, ICMP


def format_payload(payload_bytes, max_len=64):
    if not payload_bytes:
        return ''

    try:
        text = payload_bytes.decode('utf-8', errors='replace')
    except Exception:
        text = ''

    hexed = binascii.hexlify(payload_bytes[:max_len]).decode('ascii')
    return f"Payload(len={len(payload_bytes)}) text={repr(text[:200])} hex={hexed}"


def process_packet(pkt):
    ts = getattr(pkt, "time", None)

    if IP in pkt:
        ip = pkt[IP]
        src = ip.src
        dst = ip.dst
        proto = ip.proto
    else:
        src = dst = proto = None

    proto_name = "OTHER"
    sport = dport = ''
    payload = b''

    if TCP in pkt:
        proto_name = "TCP"
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        payload = raw(pkt[TCP].payload) if pkt[TCP].payload else b''
    elif UDP in pkt:
        proto_name = "UDP"
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        payload = raw(pkt[UDP].payload) if pkt[UDP].payload else b''
    elif ICMP in pkt:
        proto_name = "ICMP"
        payload = raw(pkt[ICMP].payload) if pkt[ICMP].payload else b''
    elif IP in pkt and pkt[IP].payload:
        payload = raw(pkt[IP].payload)

    line = f"[{ts}] {src}:{sport} -> {dst}:{dport} {proto_name} len={len(pkt)}"
    print(line)

    if payload:
        print("  " + format_payload(payload))


def live_sniff(iface=None, count=0, outfile=None, bpf_filter=None):
    writer = None

    if outfile:
        writer = PcapWriter(outfile, append=True, sync=True)
        print(f"Writing captured packets to {outfile}")

    def _prn(pkt):
        process_packet(pkt)
        if writer:
            writer.write(pkt)

    print(f"Starting sniff on iface={iface} count={count or 'infinite'} filter={bpf_filter}")
    sniff(iface=iface, prn=_prn, store=0, count=count if count > 0 else 0, filter=bpf_filter)


def read_pcap(path):
    print(f"Reading pcap from {path}")
    for pkt in rdpcap(path):
        process_packet(pkt)


def main():
    parser = argparse.ArgumentParser(description="Basic Network Sniffer (requires root/admin).")
    parser.add_argument("--iface", "-i", help="Network interface to sniff on")
    parser.add_argument("--count", "-c", type=int, default=0, help="Number of packets to capture (0 = infinite)")
    parser.add_argument("--outfile", "-o", help="Write captured packets to pcap file")
    parser.add_argument("--read", "-r", help="Read packets from existing pcap file instead of live capture")
    parser.add_argument("--filter", "-f", help="BPF filter (tcp, udp, port 80, etc.)")
    args = parser.parse_args()

    if args.read:
        read_pcap(args.read)
    else:
        try:
            live_sniff(iface=args.iface, count=args.count, outfile=args.outfile, bpf_filter=args.filter)
        except PermissionError:
            print("Permission denied: run as root/Administrator or install Npcap on Windows and run with admin rights.", file=sys.stderr)
        except KeyboardInterrupt:
            print("\nStopped by user.")


if __name__ == "__main__":
    main()
