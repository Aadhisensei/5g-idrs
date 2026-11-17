"""
GTP-U sensor (N3, UDP 2152) -- for rule T09 (GTP abuse: TEID with no matching PFCP session).

N3 runs gNB <-> UPF, so it is NOT visible on the Core VM. Deploy this container on the UPF VM
(or the gNB VM) with REDIS_HOST pointing at the Core VM, and protect that Redis (firewall/auth).
One event per (src, dst, TEID) per second with the packet count, so user traffic cannot flood Redis.
"""
import os
import struct
import sys
import threading
import time

sys.path.insert(0, "/app")
from scapy.all import sniff, IP, UDP, Raw

from common.events import IDRSEvent
from common.redis_client import get_redis, publish_event

IFACE = os.environ.get("GTPU_IFACE", "eth1")
r = get_redis()
_agg, _lock = {}, threading.Lock()
TYPES = {1: "Echo Request", 2: "Echo Response", 26: "Error Indication", 254: "End Marker", 255: "G-PDU"}


def parse_gtpu(payload: bytes):
    if len(payload) < 8 or (payload[0] >> 5) != 1:
        return None
    return {"msg_type_code": payload[1], "msg_type": TYPES.get(payload[1], f"Unknown({payload[1]})"),
            "teid": struct.unpack("!I", payload[4:8])[0], "length": struct.unpack("!H", payload[2:4])[0]}


def handle(pkt):
    if IP not in pkt or UDP not in pkt or Raw not in pkt:
        return
    g = parse_gtpu(bytes(pkt[Raw].load))
    if not g:
        return
    key = (pkt[IP].src, pkt[IP].dst, g["msg_type"], g["teid"], pkt[UDP].dport)
    with _lock:
        _agg[key] = _agg.get(key, 0) + 1


def flusher():
    while True:
        time.sleep(1.0)
        with _lock:
            items, _agg_copy = list(_agg.items()), _agg.clear()
        for (src, dst, mt, teid, dport), n in items:
            publish_event(r, IDRSEvent(parser="gtpu", interface="N3", msg_type=mt, src_ip=src, dst_ip=dst,
                                       fields={"teid": teid, "count": n, "dst_port": dport}))


if __name__ == "__main__":
    print(f"[GTP-U sensor] iface={IFACE} udp 2152", flush=True)
    threading.Thread(target=flusher, daemon=True).start()
    sniff(iface=IFACE, filter="udp port 2152", prn=handle, store=False)
