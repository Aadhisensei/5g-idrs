"""
NGAP parser (N2 interface: gNB <-> AMF, SCTP/38412).

Uses pycrate's compiled NGAP ASN.1 module for full APER decode.
Extracts procedureCode, AMF-UE-NGAP-ID, RAN-UE-NGAP-ID, NAS-PDU IE,
and cause IE using pycrate's protocolIEs list -- no manual byte offsets.

Falls back to raw-hex publish if pycrate is unavailable or decode fails
so no traffic is ever silently dropped.

NAS-PDU bytes are forwarded to nas:raw for the NAS parser.

3GPP TS 38.413 -- NGAP Protocol Specification
"""
import os
import sys

sys.path.insert(0, "/app")
from scapy.all import sniff, IP
from scapy.layers.sctp import SCTP, SCTPChunkData

from common.events import IDRSEvent
from common.redis_client import get_redis, publish_event, xadd_capped, NAS_RAW_STREAM

IFACE = os.environ.get("NGAP_IFACE", "eth1")
PORT  = int(os.environ.get("NGAP_PORT", "38412"))

r = get_redis()

# ------------------------------------------------------------------
# pycrate import
# ------------------------------------------------------------------
try:
    from pycrate_asn1dir import NGAP as NGAP_ASN1
    HAVE_PYCRATE = True
except Exception:
    HAVE_PYCRATE = False

# ------------------------------------------------------------------
# NGAP procedure names (TS 38.413 §9.3.8)
# ------------------------------------------------------------------
PROCEDURE_NAMES = {   # fallback only; pycrate's own message name is preferred
    0: "AMFConfigurationUpdate", 1: "AMFStatusIndication", 4: "DownlinkNASTransport",
    14: "InitialContextSetup", 15: "InitialUEMessage", 17: "LocationReportingFailureIndication",
    21: "NGSetup", 26: "PDUSessionResourceModify", 29: "PDUSessionResourceSetup",
    33: "PWSFailureIndication", 35: "RANConfigurationUpdate", 41: "UEContextRelease",
    46: "UplinkNASTransport", 48: "UplinkRANConfigurationTransfer",
}

# NGAP IE IDs we care about (TS 38.413 §9.3.1.1)
IE_AMF_UE_NGAP_ID = 10
IE_RAN_UE_NGAP_ID = 85
IE_NAS_PDU        = 38
IE_CAUSE          = 15
IE_USER_LOC_INFO  = 121

# ------------------------------------------------------------------
# Full pycrate decode
# ------------------------------------------------------------------

def decode_ngap(payload: bytes) -> dict:
    """
    Attempt full APER decode via pycrate.
    Returns a dict with decoded=True and all extracted IE fields,
    or decoded=False + raw_hex on any failure.
    """
    if not HAVE_PYCRATE:
        return {
            "decoded": False,
            "reason": "pycrate not available",
            "raw_hex": payload.hex(),
        }

    try:
        pdu = NGAP_ASN1.NGAP_PDU_Descriptions.NGAP_PDU
        pdu.from_aper(payload)
        val = pdu.get_val()

        # val: ('initiatingMessage' | 'successfulOutcome' | 'unsuccessfulOutcome',
        #        {'procedureCode': int, 'criticality': str,
        #         'value': ('MessageTypeName', {inner_dict})})
        choice  = val[0]
        content = val[1]

        proc_code = content.get("procedureCode")
        _v = content.get("value")
        asn_name = _v[0] if isinstance(_v, (list, tuple)) and _v else None
        proc_name = asn_name or PROCEDURE_NAMES.get(proc_code, f"Unknown({proc_code})")

        # Walk protocolIEs list to extract IE values by ID
        ie_container = content.get("value", (None, {}))[1]
        ie_list      = ie_container.get("protocolIEs", [])

        amf_ue_id  = None
        ran_ue_id  = None
        nas_pdu    = None
        cause      = None

        for ie in ie_list:
            ie_id  = ie.get("id")
            ie_val = ie.get("value", (None, None))
            # ie_val is a 2-tuple: (TypeName, value)
            typed_val = ie_val[1] if isinstance(ie_val, (list, tuple)) and len(ie_val) > 1 else ie_val

            if ie_id == IE_AMF_UE_NGAP_ID:
                amf_ue_id = int(typed_val) if typed_val is not None else None

            elif ie_id == IE_RAN_UE_NGAP_ID:
                ran_ue_id = int(typed_val) if typed_val is not None else None

            elif ie_id == IE_NAS_PDU:
                # pycrate returns NAS-PDU as bytes or bytearray
                if isinstance(typed_val, (bytes, bytearray)):
                    nas_pdu = bytes(typed_val)

            elif ie_id == IE_CAUSE:
                # cause is ('radioNetwork'|'transport'|..., int_or_enum)
                if isinstance(typed_val, (list, tuple)) and len(typed_val) == 2:
                    cause = f"{typed_val[0]}:{typed_val[1]}"
                else:
                    cause = str(typed_val)

        return {
            "decoded":        True,
            "choice":         str(choice),
            "procedure_code": proc_code,
            "procedure_name": proc_name,
            "amf_ue_ngap_id": amf_ue_id,
            "ran_ue_ngap_id": ran_ue_id,
            "has_nas_pdu":    nas_pdu is not None,
            "cause":          cause,
            "ie_count":       len(ie_list),
            "raw_hex":        payload.hex(),
            "_nas_pdu_bytes": nas_pdu,   # internal — stripped before Redis publish
        }

    except Exception as exc:
        return {
            "decoded":  False,
            "reason":   str(exc),
            "raw_hex":  payload.hex(),
        }


def forward_nas(nas_bytes: bytes, src_ip: str, dst_ip: str, amf_ue=None, ran_ue=None):
    """Forward extracted NAS PDU bytes to the NAS parser via nas:raw (with the NGAP UE ids,
    so the engine can bind a subscriber identity to later NGAP events of the same UE)."""
    xadd_capped(r, NAS_RAW_STREAM, {
        "data":    nas_bytes.hex(),
        "src_ip":  src_ip or "",
        "dst_ip":  dst_ip or "",
        "amf_ue_ngap_id": "" if amf_ue is None else str(amf_ue),
        "ran_ue_ngap_id": "" if ran_ue is None else str(ran_ue),
    })


def handle(pkt):
    if not pkt.haslayer(SCTP) or IP not in pkt:
        return
    if pkt[SCTP].dport != PORT and pkt[SCTP].sport != PORT:
        return

    layer = pkt.getlayer(SCTPChunkData)
    while layer:
        payload = bytes(layer.data) if layer.data else b""
        if not payload:
            layer = layer.payload.getlayer(SCTPChunkData) if layer.payload else None
            continue

        parsed = decode_ngap(payload)

        # Pull out NAS PDU before stripping internal field
        nas_bytes = parsed.pop("_nas_pdu_bytes", None)

        # If pycrate decode failed, fall back to heuristic NAS scan
        if not parsed.get("decoded"):
            idx = payload.find(b"\x7e")
            if idx != -1 and idx + 2 < len(payload):
                nas_bytes = payload[idx:]

        proc_name = parsed.get("procedure_name", "undecoded")

        event = IDRSEvent(
            parser     = "ngap",
            interface  = "N2",
            msg_type   = proc_name,
            src_ip     = pkt[IP].src,
            dst_ip     = pkt[IP].dst,
            fields     = parsed,
        )
        publish_event(r, event)

        # Forward NAS PDU to NAS parser
        if nas_bytes:
            forward_nas(nas_bytes, pkt[IP].src, pkt[IP].dst,
                        parsed.get("amf_ue_ngap_id"), parsed.get("ran_ue_ngap_id"))

        status = (
            f"decoded={parsed['decoded']} "
            f"ue={parsed.get('amf_ue_ngap_id')}/{parsed.get('ran_ue_ngap_id')} "
            f"nas={parsed.get('has_nas_pdu', False)}"
            if parsed.get("decoded")
            else f"decoded=False reason={parsed.get('reason', '')[:60]}"
        )
        print(f"[NGAP] {proc_name} {pkt[IP].src}->{pkt[IP].dst} {status}", flush=True)

        layer = layer.payload.getlayer(SCTPChunkData) if layer.payload else None


if __name__ == "__main__":
    print(
        f"[NGAP parser] sniffing iface={IFACE} sctp port {PORT} "
        f"(pycrate: {HAVE_PYCRATE})",
        flush=True
    )
    sniff(iface=IFACE, filter=f"sctp and port {PORT}", prn=handle, store=False)
