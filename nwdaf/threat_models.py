"""
nwdaf/threat_models.py
Data models for the Threat Evaluation Engine.
"""
import dataclasses
import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional


class Severity(str, Enum):
    """Thesis Table 3.3 tiers on the 0-100 score: INFO 0-39, WARNING 40-69, CRITICAL 70-100."""
    INFO     = "INFO"
    WARNING  = "WARNING"
    CRITICAL = "CRITICAL"


class ThreatCategory(str, Enum):
    SIGNALLING_FLOOD     = "SIGNALLING_FLOOD"
    SESSION_MANIPULATION = "SESSION_MANIPULATION"
    AUTH_ABUSE           = "AUTH_ABUSE"
    UNAUTHORIZED_API     = "UNAUTHORIZED_API"
    DATA_EXFILTRATION    = "DATA_EXFILTRATION"
    ROGUE_NF             = "ROGUE_NF"
    TUNNEL_ABUSE         = "TUNNEL_ABUSE"
    CROSS_INTERFACE      = "CROSS_INTERFACE"
    POLICY_TAMPERING     = "POLICY_TAMPERING"


@dataclasses.dataclass
class ThreatEvent:
    rule_id:     str
    rule_name:   str
    category:    ThreatCategory
    score:       float
    severity:    Severity
    supi:        Optional[str]
    src_ip:      Optional[str]
    interface:   str
    parser:      str
    trigger_msg: str
    evidence:    Dict[str, Any]
    detected_at: float = dataclasses.field(default_factory=time.time)
    threat_id:   str   = dataclasses.field(
                           default_factory=lambda: str(uuid.uuid4())
                         )

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["category"] = self.category.value
        d["severity"] = self.severity.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str)

    @staticmethod
    def from_dict(d: dict) -> "ThreatEvent":
        d = dict(d)
        for k in ("forwarded", "suppressed", "recommended_action", "tier"):
            d.pop(k, None)
        d["category"] = ThreatCategory(d["category"])
        d["severity"] = Severity(d["severity"])
        return ThreatEvent(**d)


def score_to_severity(score: float) -> Severity:
    if score >= 70: return Severity.CRITICAL
    if score >= 40: return Severity.WARNING
    return Severity.INFO
