"""
Shared IDRS event schema.

Every protocol parser publishes events in this exact shape to the Redis
Streams channel `ids:events`. Downstream modules (NWDAF aggregator, and
later the Threat Evaluation Engine) only ever depend on this schema, not
on any parser-internal representation.

Field names intentionally mirror Chapter 3 of the thesis (§3.4.3):
parser, interface, timestamp, src_ip, dst_ip, supi, session_id, msg_type,
fields.
"""
import dataclasses
import json
import time
import uuid
from typing import Any, Dict, Optional


@dataclasses.dataclass
class IDRSEvent:
    parser: str                 # e.g. "sbi_http2", "pfcp", "ngap", "nas", "gtpv2c", "diameter"
    interface: str              # e.g. "SBI", "N4", "N2", "N1", "S11", "S6a"
    msg_type: str                # human-readable message/procedure name
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    supi: Optional[str] = None
    session_id: Optional[str] = None
    fields: Dict[str, Any] = dataclasses.field(default_factory=dict)
    timestamp: float = dataclasses.field(default_factory=time.time)
    event_id: str = dataclasses.field(default_factory=lambda: str(uuid.uuid4()))

    def to_json(self) -> str:
        return json.dumps(dataclasses.asdict(self), default=str)

    @staticmethod
    def from_json(raw: str) -> "IDRSEvent":
        d = json.loads(raw)
        return IDRSEvent(**d)
