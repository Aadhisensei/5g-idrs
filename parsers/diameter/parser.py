"""
Diameter parser (S6a-equivalent, legacy/NSA interface).

Not used by this SA testbed's Open5GS deployment -- included as a
skeleton for NSA/EPC extension (Chapter 5 Future Work). Sniffs
TCP/3868 and decodes only the Diameter fixed header (Command Code,
Application ID); AVP-level decode is left for the NSA extension phase.
"""
import os
import sys
import struct

sys.path.insert(0, "/app")
from scapy.all import sniff, TCP, IP  # noqa: E402

from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event  # noqa: E402

IFACE = os.environ.get("DIAMETER_IFACE", "eth1")
PORT = int(os.environ.get("DIAMETER_PORT", "3868"))

r = get_redis()

COMMAND_CODES = {
    257: "Capabilities-Exchange", 272: "Credit-Control",
    316: "Update-Location", 318: "Authentication-Information",
    321: "Purge-UE",
}


def parse_diameter_header(payload: bytes):
    if len(payload) < 20:
        return None
    version = payload[0]
    if version != 1:
        return None
    length = int.from_bytes(payload[1:4], "big")
    flags = payload[4]
    command_code = int.from_bytes(payload[5:8], "big")
    app_id = struct.unpack("!I", payload[8:12])[0]
    is_request = bool(flags & 0x80)
    return {
        "length": length,
        "command_code": command_code,
        "command_name": COMMAND_CODES.get(command_code, f"Unknown({command_code})"),
        "application_id": app_id,
        "is_request": is_request,
    }


def handle(pkt):
    if TCP not in pkt or IP not in pkt:
        return
    if pkt[TCP].dport != PORT and pkt[TCP].sport != PORT:
        return
    payload = bytes(pkt[TCP].payload)
    parsed = parse_diameter_header(payload)
    if not parsed:
        return
    event = IDRSEvent(
        parser="diameter", interface="S6a",
        msg_type=f"{parsed['command_name']} ({'Req' if parsed['is_request'] else 'Ans'})",
        src_ip=pkt[IP].src, dst_ip=pkt[IP].dst, fields=parsed,
    )
    publish_event(r, event)
    print(f"[Diameter] {event.msg_type} {pkt[IP].src}->{pkt[IP].dst}", flush=True)


if __name__ == "__main__":
    print(f"[Diameter parser] sniffing iface={IFACE} tcp port {PORT} "
          f"(expect silence on a pure 5G-SA testbed)", flush=True)
    sniff(iface=IFACE, filter=f"tcp port {PORT}", prn=handle, store=False)
