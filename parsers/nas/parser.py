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
    0x4c: "Service Request", 0x4d: "Service Reject", 0x4e: "Service Accept",
    0x54: "Configuration Update Command", 0x55: "Configuration Update Complete",
    0x56: "Authentication Request", 0x57: "Authentication Response",
    0x58: "Authentication Reject", 0x59: "Authentication Failure",
    0x5a: "Authentication Result",
    0x5b: "Identity Request", 0x5c: "Identity Response",
    0x5d: "Security Mode Command", 0x5e: "Security Mode Complete",
    0x5f: "Security Mode Reject",
    0x64: "5GMM Status", 0x65: "Notification", 0x66: "Notification Response",
    0x67: "UL NAS Transport", 0x68: "DL NAS Transport",
}

EXT_PROTOCOL_DISCRIMINATOR_5GMM = 0x7E


def parse_mobile_identity(buf: bytes, pos: int):
    """5GS mobile identity (LV-E at buf[pos]: 2-byte length, then value). TS 24.501 9.11.3.4.
    Returns {} or {identity_type, suci, supi}. SUPI is derived only for the *null* protection
    scheme (UERANSIM default); ECIES-protected SUCIs stay opaque (no false identity)."""
    if len(buf) < pos + 3:
        return {}
    ln = int.from_bytes(buf[pos:pos + 2], "big")
    v = buf[pos + 2:pos + 2 + ln]
    if not v:
        return {}
    t = v[0] & 0x07
    if t == 2:
        return {"identity_type": "5G-GUTI"}
    if t != 1 or len(v) < 8:
        return {"identity_type": {3: "IMEI", 4: "5G-S-TMSI", 5: "IMEISV"}.get(t, str(t))}
    d = lambda b: (b & 0x0F, b >> 4)
    mcc1, mcc2 = d(v[1]); mcc3, mnc3 = d(v[2]); mnc1, mnc2 = d(v[3])
    mcc = f"{mcc1}{mcc2}{mcc3}"; mnc = f"{mnc1}{mnc2}" + ("" if mnc3 == 0xF else str(mnc3))
    scheme = v[6] & 0x0F
    out = {"identity_type": "SUCI", "protection_scheme": scheme, "mcc": mcc, "mnc": mnc,
           "suci": f"suci-0-{mcc}-{mnc}-{v[4:6].hex()}-{scheme}-{v[7]}-{v[8:].hex()}"}
    if scheme == 0 and (v[0] >> 4) & 0x07 == 0:        # null scheme, IMSI format
        msin = ""
        for b in v[8:]:
            lo, hi = b & 0x0F, b >> 4
            msin += (str(lo) if lo != 0xF else "") + (str(hi) if hi != 0xF else "")
        out["supi"] = f"imsi-{mcc}{mnc}{msin}"
    return out


def decode_nas(payload: bytes):
    """payload is expected to start at the 0x7E EPD byte (as located by
    the NGAP parser's heuristic scan)."""
    if len(payload) < 3 or payload[0] != EXT_PROTOCOL_DISCRIMINATOR_5GMM:
        return None

    sec_header = payload[1] & 0x0F
    if sec_header != 0:
        # Security-protected NAS (TS 24.501 9.1.1): EPD | sec hdr | MAC(4) | SQN(1) | inner NAS message.
        # With integrity-only protection or NEA0 (null cipher -- what the testbed UE log shows) the inner
        # message is plaintext. It is accepted only if it looks like a plain 5GMM message (EPD 0x7E,
        # security header 0, known type), so genuinely ciphered payloads are never mis-decoded.
        inner = payload[7:]
        if len(inner) >= 3 and inner[0] == EXT_PROTOCOL_DISCRIMINATOR_5GMM and (inner[1] & 0x0F) == 0 \
                and inner[2] in MM_MSG_TYPES:
            out = decode_nas(inner) or {}
            out.update({"security_header_type": sec_header, "inner_decoded": True,
                        "outer_security": "integrity-protected" if sec_header in (1, 3) else "NEA0 (null cipher) or plaintext inner"})
            return out
        return {
            "decoded": False,
            "security_header_type": sec_header,
            "reason": "ciphered or integrity-protected NAS payload",
        }

    msg_type_octet = payload[2]
    out = {
        "decoded": True,
        "security_header_type": sec_header,
        "msg_type_code": hex(msg_type_octet),
        "msg_type": MM_MSG_TYPES.get(msg_type_octet, f"Unknown(0x{msg_type_octet:02x})"),
    }
    try:
        if msg_type_octet == 0x41:        # Registration Request: reg type/ngKSI (1 octet), then mobile identity
            out.update(parse_mobile_identity(payload, 4))
        elif msg_type_octet == 0x5C:      # Identity Response: mobile identity right after the header
            out.update(parse_mobile_identity(payload, 3))
    except Exception:
        pass
    return out


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

                for k in ("amf_ue_ngap_id", "ran_ue_ngap_id"):
                    if fields.get(k):
                        parsed[k] = int(fields[k])
                event = IDRSEvent(
                    parser="nas",
                    interface="N1",
                    msg_type=parsed.get("msg_type", "undecoded (ciphered)"),
                    src_ip=fields.get("src_ip") or None,
                    dst_ip=fields.get("dst_ip") or None,
                    supi=parsed.get("supi"),
                    fields=parsed,
                )
                publish_event(r, event)
                print(f"[NAS] {event.msg_type} {event.src_ip}->{event.dst_ip}", flush=True)


if __name__ == "__main__":
    main()
