"""
SBI/HTTP2 parser (Service-Based Interface: all NF <-> NF traffic).

On the Core VM, every NF's SBI listens on loopback (127.0.0.x:7777 -
see Table in methodology). We capture on `lo` and let tshark's mature
HTTP/2 dissector handle TCP reassembly and HPACK decompression --
hand-rolling HTTP/2 frame reassembly with raw scapy is fragile and not
worth reimplementing when tshark already does it correctly.

Extracts :method, :path and :status pseudo-headers per request/response,
which is enough for threat rules T01 (NF Registration Flood), T07
(Unauthorized API), and T08 (Rogue NF) once the Threat Evaluation Engine
is built in Phase 2.
"""
import os
import sys

sys.path.insert(0, "/app")
import pyshark  # noqa: E402

from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event  # noqa: E402

IFACE = os.environ.get("SBI_IFACE", "lo")
PORT = os.environ.get("SBI_PORT", "7777")

r = get_redis()


def extract_supi(path: str):
    """Best-effort SUPI/IMSI extraction from well-known SBI URL patterns,
    e.g. .../nudm-sdm/v2/imsi-999700000000001/... """
    if not path:
        return None
    for token in path.split("/"):
        if token.startswith("imsi-") or token.startswith("suci-"):
            return token
    return None


def main():
    cap = pyshark.LiveCapture(
        interface=IFACE,
        bpf_filter=f"tcp port {PORT}",
        decode_as={f"tcp.port=={PORT}": "http2"},
    )
    print(f"[SBI parser] sniffing iface={IFACE} tcp port {PORT}", flush=True)

    for pkt in cap.sniff_continuously():
        try:
            if not hasattr(pkt, "http2"):
                continue
            # Skip fragments still awaiting TCP reassembly -- the real,
            # fully-decoded HTTP/2 headers only appear on the packet that
            # completes reassembly. Processing the fragment early is what
            # produces spurious "RESPONSE None" / method-less events.
            if hasattr(pkt, "tcp") and hasattr(pkt.tcp, "reassembled_in"):
                continue

            for h2 in pkt.get_multiple_layers("http2"):
                method = getattr(h2, "headers_method", None)
                path = getattr(h2, "headers_path", None)
                status = getattr(h2, "headers_status", None)
                if not (method or path or status):
                    continue

                src = pkt.ip.src if hasattr(pkt, "ip") else None
                dst = pkt.ip.dst if hasattr(pkt, "ip") else None

                msg_type = f"{method} {path}" if method else f"RESPONSE {status}"

                event = IDRSEvent(
                    parser="sbi_http2",
                    interface="SBI",
                    msg_type=msg_type.strip(),
                    src_ip=src,
                    dst_ip=dst,
                    supi=extract_supi(str(path)) if path else None,
                    fields={
                        "method": str(method) if method else None,
                        "path": str(path) if path else None,
                        "status": str(status) if status else None,
                    },
                )
                publish_event(r, event)
                print(f"[SBI] {event.msg_type} {src}->{dst}", flush=True)
        except Exception as e:
            print(f"[SBI parser] error on packet: {e}", flush=True)


if __name__ == "__main__":
    main()
