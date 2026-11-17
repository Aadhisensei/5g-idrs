"""
nwdaf/alert_manager.py
Tiered Alert Manager — Phase 3

Sits between the Threat Engine and the Mitigation Module.

Responsibilities (per PDF §4.4 Module 3):
  1. Deduplicate — suppress repeat alerts for the same rule+key
     within a cooldown window so one flood doesn't generate thousands
     of identical alerts.
  2. Tier filter — only forward HIGH / CRITICAL severity alerts
     to the Mitigation Module; LOW / MEDIUM go to the log only.
  3. Enrich — attach recommended mitigation action to each alert
     before forwarding.
  4. Publish — write actionable alerts to Redis stream `ids:alerts`
     so the Mitigation Module (Phase 4) can consume them.
  5. Log — keep a bounded in-memory history of all alerts (all tiers)
     exposed via REST for the operator dashboard.
"""

import json
import os
import threading
import time
import urllib.request
from collections import defaultdict, deque
from typing import Callable, Deque, Dict, List, Optional

from common.redis_client import xadd_capped, ALERTS_STREAM
from nwdaf.threat_models import ThreatEvent, Severity


# ------------------------------------------------------------------
# Recommended mitigation action per rule
# (used by Mitigation Module in Phase 4)
# ------------------------------------------------------------------
RULE_MITIGATIONS = {
    # Thesis Table 3.4 where it can be done through the SBI with identifiers the pipeline really has.
    "T01": "reject_nf_registration",   # delete the flooding (not-yet-established) NF instances at the NRF
    "T08": "reject_nf_registration",   # delete the rogue NF instance (id known from the registry)
    "T02": "terminate_session",        # needs smContextRef (skipped if unknown)
    "T04": "terminate_session",        # needs smContextRef (skipped if unknown)
    "T03": "notify_operator",          # thesis: PFCP Session Deletion to the UPF (not possible from the NWDAF)
    "T09": "notify_operator",
    "T05": "notify_operator",          # thesis: iptables rate-limit of the requestor NF
    "T06": "notify_operator",          # thesis: PCF QoS throttle
    "T07": "notify_operator",
    "T10": "notify_operator",          # thesis: webhook + PCF restore
    "X01": "notify_operator", "X02": "notify_operator", "X03": "notify_operator",
}


# ------------------------------------------------------------------
# Alert record (wraps ThreatEvent with manager-added fields)
# ------------------------------------------------------------------

class Alert:
    def __init__(self,
                 threat:     ThreatEvent,
                 forwarded:  bool,
                 suppressed: bool,
                 mitigation: Optional[str]):
        self.threat      = threat
        self.forwarded   = forwarded    # sent to Mitigation Module?
        self.suppressed  = suppressed   # deduplicated?
        self.mitigation  = mitigation   # recommended action
        self.created_at  = time.time()

    def to_dict(self) -> dict:
        d = self.threat.to_dict()
        d["tier"]             = d["severity"]
        d["forwarded"]        = self.forwarded
        d["suppressed"]       = self.suppressed
        d["recommended_action"] = self.mitigation
        return d


# ------------------------------------------------------------------
# AlertManager
# ------------------------------------------------------------------

class AlertManager:
    """
    Instantiated once in app.py.
    Receives ThreatEvent objects via receive() and decides
    whether to suppress, log, or forward them.
    """

    # Cooldown: same rule + key won't fire again within this window
    COOLDOWN_SEC = {
        "T01": 30, "T02": 15, "T03": 15, "T04": 20, "T05": 20, "T06": 30, "T07": 10, "T08": 10, "T09": 20,
        "T10": 20, "X01": 20, "X02": 20, "X03": 30,
    }
    DEFAULT_COOLDOWN = 20

    # Only these severities are forwarded to Mitigation Module
    # Thesis Table 3.3: only CRITICAL triggers Module 4; WARNING also goes to the webhook (if configured)
    FORWARD_SEVERITIES = {Severity.CRITICAL}
    WEBHOOK_URL = os.environ.get("IDRS_WEBHOOK_URL", "")

    # Max alert history kept in memory
    MAX_HISTORY = 1000
    STALE_SEC = 60.0

    def __init__(self,
                 forward_callback: Callable[[Alert], None] = None,
                 redis_client = None,
                 store = None):
        """
        forward_callback : called for every HIGH/CRITICAL alert
                           (Phase 4 wires in Mitigator.handle here)
        redis_client     : if provided, actionable alerts are also
                           published to ids:alerts Redis stream
        """
        self.forward_callback = forward_callback or (lambda a: None)
        self._redis           = redis_client
        self._store           = store

        # Dedup store: (rule_id, dedup_key) -> last_alert_time
        self._last_alert: Dict[tuple, float] = {}
        self._dedup_lock  = threading.Lock()

        # Alert history (all tiers)
        self._history: Deque[Alert] = deque(maxlen=self.MAX_HISTORY)
        self._hist_lock = threading.Lock()

        # Counters
        self._received   = 0
        self._suppressed = 0
        self._forwarded  = 0

    # ------------------------------------------------------------------
    # Main entry point — called by ThreatEngine alert_callback
    # ------------------------------------------------------------------

    def receive(self, threat: ThreatEvent):
        """Process one ThreatEvent from the Threat Engine."""
        self._received += 1

        dedup_key  = self._make_dedup_key(threat)
        suppressed = self._is_suppressed(threat, dedup_key)

        mitigation = RULE_MITIGATIONS.get(threat.rule_id)
        # The consumer replays ids:events from the start: never act on stale history.
        stale = (time.time() - threat.detected_at) > self.STALE_SEC
        should_forward = (
            not suppressed and not stale
            and threat.severity in self.FORWARD_SEVERITIES
        )

        alert = Alert(
            threat     = threat,
            forwarded  = should_forward,
            suppressed = suppressed,
            mitigation = mitigation,
        )

        # Always log
        with self._hist_lock:
            self._history.append(alert)
        if self._store and not suppressed:      # suppressed repeats are counted, not persisted
            try:
                self._store.save_alert(alert.to_dict())
            except Exception as exc:
                print(f"[AlertManager] store error: {exc}", flush=True)

        if suppressed:
            self._suppressed += 1
            return
        if not stale and self.WEBHOOK_URL and threat.severity in (Severity.WARNING, Severity.CRITICAL):
            self._webhook(alert)

        # Update dedup timestamp
        with self._dedup_lock:
            self._last_alert[dedup_key] = time.time()

        if should_forward:
            self._forwarded += 1
            self._forward(alert)

    # ------------------------------------------------------------------
    # Accessors for REST endpoints
    # ------------------------------------------------------------------

    def _webhook(self, alert):
        """WARNING/CRITICAL -> POST to the configured notification webhook (thesis Table 3.3); never blocks."""
        body = json.dumps(alert.to_dict(), default=str).encode()
        def go():
            try:
                req = urllib.request.Request(self.WEBHOOK_URL, data=body, headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=3).read()
            except Exception as exc:
                print(f"[AlertManager] webhook error: {exc}", flush=True)
        threading.Thread(target=go, daemon=True).start()

    def restore(self, rows: List[dict]):
        """Reload persisted alerts into the in-memory history after a restart (no side effects)."""
        with self._hist_lock:
            for d in rows:
                try:
                    a = Alert(ThreatEvent.from_dict(d), bool(d.get("forwarded")),
                              bool(d.get("suppressed")), d.get("recommended_action"))
                    self._history.append(a)
                except Exception:
                    continue

    def get_history(self,
                    limit:     int           = 100,
                    rule_id:   Optional[str] = None,
                    severity:  Optional[str] = None,
                    forwarded: Optional[bool]= None) -> List[Alert]:
        with self._hist_lock:
            items = list(self._history)
        if rule_id:
            items = [a for a in items if a.threat.rule_id  == rule_id.upper()]
        if severity:
            items = [a for a in items if a.threat.severity == severity.upper()]
        if forwarded is not None:
            items = [a for a in items if a.forwarded == forwarded]
        return items[-limit:]

    def stats(self) -> dict:
        return {
            "received":   self._received,
            "suppressed": self._suppressed,
            "forwarded":  self._forwarded,
            "history_len": len(self._history),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _make_dedup_key(threat: ThreatEvent) -> tuple:
        """
        Key that identifies 'the same alert'.
        Same rule + same source (SUPI if available, else src_ip).
        """
        source = threat.supi or threat.src_ip or "unknown"
        return (threat.rule_id, source)

    def _is_suppressed(self, threat: ThreatEvent, key: tuple) -> bool:
        cooldown = self.COOLDOWN_SEC.get(threat.rule_id, self.DEFAULT_COOLDOWN)
        with self._dedup_lock:
            last = self._last_alert.get(key)
        if last is None:
            return False
        return (time.time() - last) < cooldown

    def _forward(self, alert: Alert):
        """Forward to Mitigation Module callback and Redis stream."""
        # Callback (Phase 4: Mitigator.handle)
        try:
            self.forward_callback(alert)
        except Exception as exc:
            print(f"[AlertManager] forward_callback error: {exc}", flush=True)

        # Redis publish (ids:alerts stream)
        if self._redis:
            try:
                xadd_capped(self._redis, ALERTS_STREAM, {
                    "data":       alert.threat.to_json(),
                    "mitigation": alert.mitigation or "",
                })
            except Exception as exc:
                print(f"[AlertManager] redis publish error: {exc}", flush=True)

        print(
            f"[ALERT] ▶ FORWARDED {alert.threat.rule_id} "
            f"{alert.threat.severity.value} score={alert.threat.score} "
            f"action={alert.mitigation} supi={alert.threat.supi} "
            f"src={alert.threat.src_ip}",
            flush=True,
        )
