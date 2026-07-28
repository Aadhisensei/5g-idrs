"""
NGAP parser (N2 interface: gNB <-> AMF, SCTP/38412).

NGAP uses ASN.1 APER encoding (3GPP TS 38.413). Full, robust APER
decoding needs a compiled ASN.1 module (this project uses `pycrate`,
which ships a maintained NGAP module) -- reimplementing an APER decoder
by hand is out of scope and error-prone.

Behaviour:
  - If pycrate's NGAP module is importable, we attempt a full decode and
    extract procedureCode, RAN-UE-NGAP-ID / AMF-UE-NGAP-ID, and any
    embedded NAS-PDU IE.
  - If decode fails (partial spec coverage, malformed capture, etc.) we
    fall back to publishing the raw hex payload with decoded=False, so
    no traffic is silently dropped -- failed decodes are still visible
    to the NWDAF/threat engine as low-confidence events.
  - Any embedded NAS-PDU bytes are forwarded to the `nas:raw` stream for
    the dedicated NAS parser, since NAS-5GS has no IP-layer existence of
    its own (§3.4.3 / rule T04 depends on this correlation).

STATUS: decode_ngap() is a functional skeleton, not yet validated
against a full 3GPP-conformant capture from the testbed -- treat
`decoded=True` results as provisional until cross-checked against
Wireshark's NGAP dissector on a real pcap. This mirrors the "planned
implementation" caveat in Chapter 3 of the thesis.
"""
import os
import sys

sys.path.insert(0, "/app")
from scapy.all import sniff, IP  # noqa: E402
from scapy.layers.sctp import SCTP, SCTPChunkData  # noqa: E402

from common.events import IDRSEvent  # noqa: E402
from common.redis_client import get_redis, publish_event, NAS_RAW_STREAM  # noqa: E402

IFACE = os.environ.get("NGAP_IFACE", "eth1")
PORT = int(os.environ.get("NGAP_PORT", "38412"))

r = get_redis()

try:
    from pycrate_asn1dir import NGAP as NGAP_ASN1  # type: ignore
    HAVE_PYCRATE = True
except Exception:
    HAVE_PYCRATE = False

PROCEDURE_NAMES = {
    # subset of TS 38.413 Table 9.3.8-1, extend as needed
    0: "AMFConfigurationUpdate", 1: "AMFStatusIndication", 14: "InitialContextSetup",
    15: "InitialUEMessage", 17: "NASNonDeliveryIndication", 21: "NGSetup",
    26: "PDUSessionResourceSetup", 33: "RANConfigurationUpdate", 35: "Reset",
    41: "UEContextRelease", 46: "UplinkNASTransport", 48: "DownlinkNASTransport",
}


def decode_ngap(payload: bytes):
    if not HAVE_PYCRATE:
        return {"decoded": False, "reason": "pycrate not available", "raw_hex": payload.hex()}
    try:
        pdu = NGAP_ASN1.NGAP_PDU_Descriptions.NGAP_PDU
        pdu.from_aper(payload)
        val = pdu.get_val()
        choice, content = val
        proc_code = content.get("procedureCode") if isinstance(content, dict) else None
        return {
            "decoded": True,
            "choice": str(choice),
            "procedure_code": proc_code,
            "procedure_name": PROCEDURE_NAMES.get(proc_code, f"Unknown({proc_code})"),
            "raw_hex": payload.hex(),
        }
    except Exception as e:
        return {"decoded": False, "reason": str(e), "raw_hex": payload.hex()}


def forward_nas_if_present(payload: bytes, src_ip: str, dst_ip: str):
    """Heuristic: NAS-5GS PDUs embedded in NGAP carry the Extended
    Protocol Discriminator 0x7E (5GS Mobility Management). Scan for it
    as a coarse trigger -- the NAS parser does the real decode."""
    idx = payload.find(b"\x7e")
    if idx != -1 and idx + 2 < len(payload):
        r.xadd(NAS_RAW_STREAM, {
            "data": payload[idx:].hex(),
            "src_ip": src_ip or "",
            "dst_ip": dst_ip or "",
        })


def handle(pkt):
    if not pkt.haslayer(SCTP) or IP not in pkt:
        return
    if pkt[SCTP].dport != PORT and pkt[SCTP].sport != PORT:
        return

    layer = pkt.getlayer(SCTPChunkData)
    while layer:
        payload = bytes(layer.payload) if layer.payload else b""
        if not payload:
            layer = layer.payload.getlayer(SCTPChunkData) if layer.payload else None
            continue

        parsed = decode_ngap(payload)
        proc_name = parsed.get("procedure_name", "unknown") if parsed.get("decoded") else "undecoded"

        event = IDRSEvent(
            parser="ngap",
            interface="N2",
            msg_type=proc_name,
            src_ip=pkt[IP].src,
            dst_ip=pkt[IP].dst,
            fields=parsed,
        )
        publish_event(r, event)
        forward_nas_if_present(payload, pkt[IP].src, pkt[IP].dst)
        print(f"[NGAP] {proc_name} decoded={parsed.get('decoded')} {pkt[IP].src}->{pkt[IP].dst}", flush=True)

        layer = layer.payload.getlayer(SCTPChunkData) if layer.payload else None


if __name__ == "__main__":
    print(f"[NGAP parser] sniffing iface={IFACE} sctp port {PORT} "
          f"(pycrate available: {HAVE_PYCRATE})", flush=True)
    sniff(iface=IFACE, filter=f"sctp and port {PORT}", prn=handle, store=False)
