"""
PFCP parser (N4 interface: SMF <-> UPF).

On the Core VM this observes SMF-originated PFCP traffic to the UPF VM
(192.168.56.20) over UDP/8805. Implements the basic PFCP header per
3GPP TS 29.244 §7.2 directly (no IE-level decode yet) -- enough to
support threat rule T03 (Session Manipulation: Modify/Delete with no
prior Establish for a given SEID), which only needs message type + SEID.
"""
import os
import struct
import sys

sys.path.insert(0, "/app")
from scapy.all import sniff, UDP, IP  # noqa: E402

from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event  # noqa: E402

MSG_TYPES = {
    1: "Heartbeat Request", 2: "Heartbeat Response",
    3: "PFD Management Request", 4: "PFD Management Response",
    5: "Association Setup Request", 6: "Association Setup Response",
    7: "Association Update Request", 8: "Association Update Response",
    9: "Association Release Request", 10: "Association Release Response",
    50: "Session Establishment Request", 51: "Session Establishment Response",
    52: "Session Modification Request", 53: "Session Modification Response",
    54: "Session Deletion Request", 55: "Session Deletion Response",
    56: "Session Report Request", 57: "Session Report Response",
}

IFACE = os.environ.get("PFCP_IFACE", "eth1")
PORT = int(os.environ.get("PFCP_PORT", "8805"))

r = get_redis()


def parse_pfcp_header(payload: bytes):
    """Parse the PFCP basic header. Returns None if payload is too short
    or doesn't look like PFCP."""
    if len(payload) < 4:
        return None
    b0 = payload[0]
    version = (b0 >> 5) & 0x07
    seid_flag = b0 & 0x01
    if version != 1:
        return None
    msg_type = payload[1]
    length = struct.unpack("!H", payload[2:4])[0]

    offset = 4
    seid = None
    if seid_flag:
        if len(payload) < offset + 8:
            return None
        seid = struct.unpack("!Q", payload[offset:offset + 8])[0]
        offset += 8

    seq = None
    if len(payload) >= offset + 3:
        seq = int.from_bytes(payload[offset:offset + 3], "big")

    return {
        "version": version,
        "msg_type_code": msg_type,
        "msg_type": MSG_TYPES.get(msg_type, f"Unknown({msg_type})"),
        "length": length,
        "seid": seid,
        "sequence": seq,
    }


def handle(pkt):
    if UDP not in pkt or IP not in pkt:
        return
    if pkt[UDP].dport != PORT and pkt[UDP].sport != PORT:
        return
    payload = bytes(pkt[UDP].payload)
    parsed = parse_pfcp_header(payload)
    if not parsed:
        return

    event = IDRSEvent(
        parser="pfcp",
        interface="N4",
        msg_type=parsed["msg_type"],
        src_ip=pkt[IP].src,
        dst_ip=pkt[IP].dst,
        session_id=str(parsed["seid"]) if parsed["seid"] is not None else None,
        fields=parsed,
    )
    publish_event(r, event)
    print(f"[PFCP] {parsed['msg_type']} SEID={parsed['seid']} seq={parsed['sequence']} "
          f"{pkt[IP].src}->{pkt[IP].dst}", flush=True)


if __name__ == "__main__":
    print(f"[PFCP parser] sniffing iface={IFACE} udp port {PORT}", flush=True)
    sniff(iface=IFACE, filter=f"udp port {PORT}", prn=handle, store=False)
