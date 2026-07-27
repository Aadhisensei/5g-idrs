"""
NAS parser (N1 interface: UE <-> AMF, transported inside NGAP).

NAS-5GS (TS 24.501) has no independent IP transport -- it only exists as
a payload embedded in NGAP Initial UE Message / Uplink/Downlink NAS
Transport IEs. This parser does NOT sniff a network interface; it
consumes the `nas:raw` Redis stream that the NGAP parser feeds
(§3.4.3), which keeps parser processes isolated per the "a crash in one
parser does not affect the others" design goal while reflecting NAS's
actual transport reality.

Decoding here is heuristic (message-type-octet lookup), not a full
TS 24.501 IE decode -- ciphered NAS payloads (post-Security Mode
Complete) cannot be read without the derived NAS keys, which this
passive-monitoring design does not have. Only plaintext NAS messages
(pre-security, e.g. the initial Registration Request, or messages sent
with NEA0/integrity-only) are meaningfully decodable this way.
"""
import os
import sys

sys.path.insert(0, "/app")
from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event, NAS_RAW_STREAM  # noqa: E402

r = get_redis()

# TS 24.501 Table 9.7 -- 5GS Mobility Management message types (subset)
MM_MSG_TYPES = {
    0x41: "Registration Request", 0x42: "Registration Accept",
    0x43: "Registration Complete", 0x44: "Registration Reject",
    0x45: "Deregistration Request (UE originating)",
    0x46: "Deregistration Accept (UE originating)",
    0x47: "Deregistration Request (UE terminated)",
    0x48: "Deregistration Accept (UE terminated)",
    0x4c: "Authentication Request", 0x4d: "Authentication Response",
    0x4e: "Authentication Reject", 0x4f: "Authentication Failure",
    0x5d: "Security Mode Command", 0x5e: "Security Mode Complete",
    0x5f: "Security Mode Reject",
    0x51: "5GMM Status",
}

EXT_PROTOCOL_DISCRIMINATOR_5GMM = 0x7E


def decode_nas(payload: bytes):
    """payload is expected to start at the 0x7E EPD byte (as located by
    the NGAP parser's heuristic scan)."""
    if len(payload) < 3 or payload[0] != EXT_PROTOCOL_DISCRIMINATOR_5GMM:
        return None

    sec_header = payload[1] & 0x0F
    if sec_header != 0:
        # Ciphered/integrity-protected -- message type octet is not in
        # the clear. We can still see that *a* NAS message occurred.
        return {
            "decoded": False,
            "security_header_type": sec_header,
            "reason": "ciphered or integrity-protected NAS payload",
        }

    msg_type_octet = payload[2]
    return {
        "decoded": True,
        "security_header_type": sec_header,
        "msg_type_code": hex(msg_type_octet),
        "msg_type": MM_MSG_TYPES.get(msg_type_octet, f"Unknown(0x{msg_type_octet:02x})"),
    }


def main():
    print("[NAS parser] consuming nas:raw stream", flush=True)
    last_id = "$"
    while True:
        resp = r.xread({NAS_RAW_STREAM: last_id}, block=5000, count=50)
        if not resp:
            continue
        for _stream, messages in resp:
            for msg_id, fields in messages:
                last_id = msg_id
                try:
                    payload = bytes.fromhex(fields.get("data", ""))
                except ValueError:
                    continue
                parsed = decode_nas(payload)
                if not parsed:
                    continue

                event = IDRSEvent(
                    parser="nas",
                    interface="N1",
                    msg_type=parsed.get("msg_type", "undecoded (ciphered)"),
                    src_ip=fields.get("src_ip") or None,
                    dst_ip=fields.get("dst_ip") or None,
                    fields=parsed,
                )
                publish_event(r, event)
                print(f"[NAS] {event.msg_type} {event.src_ip}->{event.dst_ip}", flush=True)


if __name__ == "__main__":
    main()
