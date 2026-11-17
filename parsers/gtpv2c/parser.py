"""
GTPv2-C parser (S11-equivalent control plane, legacy/NSA interface).

Open5GS in pure 5G-SA mode (this testbed) does not use GTPv2-C -- it's
an EPC/S11 interface relevant only to NSA (4G-anchored) deployments
(see Chapter 5, Future Work: "adding support for S11 GTPv2-C and S6a
Diameter" for NSA coverage). This parser sniffs UDP/2123 and logs
gracefully if nothing is observed, per the thesis's design intent
("handle if present, log gracefully if absent" -- §3.4.3).
"""
import os
import sys
import struct
import time

sys.path.insert(0, "/app")
from scapy.all import sniff, UDP, IP  # noqa: E402

from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event  # noqa: E402

IFACE = os.environ.get("GTP_IFACE", "eth1")
PORT = int(os.environ.get("GTP_PORT", "2123"))

r = get_redis()

MSG_TYPES = {
    32: "Create Session Request", 33: "Create Session Response",
    36: "Delete Session Request", 37: "Delete Session Response",
    34: "Modify Bearer Request", 35: "Modify Bearer Response",
    1: "Echo Request", 2: "Echo Response",
}


def parse_gtpv2c(payload: bytes):
    if len(payload) < 8:
        return None
    b0 = payload[0]
    teid_flag = (b0 >> 3) & 0x01
    msg_type = payload[1]
    length = struct.unpack("!H", payload[2:4])[0]
    offset = 4
    teid = None
    if teid_flag:
        teid = struct.unpack("!I", payload[4:8])[0]
        offset = 8
    return {
        "msg_type_code": msg_type,
        "msg_type": MSG_TYPES.get(msg_type, f"Unknown({msg_type})"),
        "length": length,
        "teid": teid,
    }


def handle(pkt):
    if UDP not in pkt or IP not in pkt:
        return
    if pkt[UDP].dport != PORT and pkt[UDP].sport != PORT:
        return
    parsed = parse_gtpv2c(bytes(pkt[UDP].payload))
    if not parsed:
        return
    event = IDRSEvent(
        parser="gtpv2c", interface="S11", msg_type=parsed["msg_type"],
        src_ip=pkt[IP].src, dst_ip=pkt[IP].dst,
        session_id=str(parsed["teid"]) if parsed["teid"] is not None else None,
        fields=parsed,
    )
    publish_event(r, event)
    print(f"[GTPv2-C] {parsed['msg_type']} TEID={parsed['teid']} {pkt[IP].src}->{pkt[IP].dst}", flush=True)


if __name__ == "__main__":
    print(f"[GTPv2-C parser] sniffing iface={IFACE} udp port {PORT} "
          f"(expect silence on a pure 5G-SA testbed)", flush=True)
    last_log = time.time()
    sniff(iface=IFACE, filter=f"udp port {PORT}", prn=handle, store=False)
