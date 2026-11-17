"""
nwdaf/threat_engine.py -- Threat Evaluation Engine (NWDAF microservice), aligned with thesis
Chapter 3 (Table 3.2 rules T01-T10, Section 3.4.4 scoring, Table 3.3 tiers).

SCORE (0-100):  S = S_base x w_recency x w_frequency
  w_recency   in [0.5, 1.0]  0.5 + 0.5*exp(-age/tau): decays with event age (tau = 30 s)
  w_frequency in [1.0, 2.0]  1 + min(1, count/ref - 1): scales with corroborating events; plus 0.25 per
                             OTHER interface that raised an anomaly for the same identity within 60 s
                             (cross-interface temporal correlation), capped at 2.0
TIERS: INFO < 40 <= WARNING < 70 <= CRITICAL   (only CRITICAL triggers the mitigator)

Thesis rules (base score)                      Needs from the parsers / environment
 T01 NF Registration Flood (70)                SBI PUT /nnrf-nfm/.../nf-instances/<id>
 T02 Session Hijack (85)                       SBI sm-contexts + User-Agent (caller NF); Location (smContextRef)
 T03 PFCP Session Manipulation (80)            PFCP F-SEID (parser)
 T04 Registration Abuse (75)                   NAS Registration Request with a null-scheme SUCI, on N2
 T05 UDM Exfiltration (65)                     SBI nudm-sdm/uecm GETs + User-Agent
 T06 Signalling Flood (60)                     any interface: PPS vs learned per-interface baseline
 T07 Unauthorized API (55)                     SBI method+path vs 3GPP service allow-list, caller matrix
 T08 Rogue NF (90)                             NRF registry snapshots (nwdaf/nrf_registry.py)
 T09 GTP Abuse (80)                            GTP-U sensor on the UPF/gNB VM (N3 is not visible on the core VM)
 T10 PCF Tampering (70)                        SBI npcf-* modifications; Location (policy ids)
Extensions (not in the thesis table): X01 NAS auth/security failure burst (65), X02 NAS identity-request
flood (65), X03 coordinated multi-interface flood (75).
Rules whose inputs are missing stay silent -- they never guess.
All windowing uses EVENT timestamps, so replayed history cannot look like live traffic.
"""
import math
import os
import re
import threading
import time
from collections import defaultdict, deque
from types import SimpleNamespace
from typing import Callable, Deque, Dict, List, Optional, Tuple

from common.events import IDRSEvent
from nwdaf.threat_models import ThreatCategory as C, ThreatEvent, score_to_severity

NF_NAMES = ("NWDAF", "AUSF", "NSSF", "SMF", "AMF", "PCF", "UDM", "UDR", "NRF", "BSF", "SCP")


def caller_nf_from(fields: dict) -> Optional[str]:
    ua = (fields.get("user_agent") or "").upper()
    for nf in NF_NAMES:
        if nf in ua:
            return nf
    return None


class SlidingWindow:
    def __init__(self, window_sec: float):
        self.window_sec, self._t = window_sec, deque()

    def hit(self, ts: float, n: int = 1) -> int:
        for _ in range(min(n, 1000)):
            self._t.append(ts)
        cutoff = ts - self.window_sec
        while self._t and self._t[0] < cutoff:
            self._t.popleft()
        return len(self._t)


class WindowRegistry:
    def __init__(self, window_sec: float, max_keys: int = 5000):
        self.window_sec, self.max_keys, self._store = window_sec, max_keys, {}

    def hit(self, rule: str, key: str, ts: float, n: int = 1) -> int:
        k = (rule, key)
        w = self._store.get(k)
        if w is None:
            if len(self._store) >= self.max_keys:
                for dk in list(self._store)[: self.max_keys // 10]:
                    del self._store[dk]
            w = self._store[k] = SlidingWindow(self.window_sec)
        return w.hit(ts, n)


# 3GPP SBI service allow-list: service -> methods Open5GS/TS 29.5xx use on it (generous on purpose)
_ALL = {"GET", "POST", "PUT", "PATCH", "DELETE"}
KNOWN_SERVICES = {
    "nnrf-nfm": _ALL, "nnrf-disc": {"GET"}, "nnrf-oauth2": {"POST"}, "oauth2": {"POST"},
    "nudm-sdm": _ALL, "nudm-uecm": _ALL, "nudm-ueau": {"GET", "POST"}, "nudm-pp": _ALL, "nudm-ee": _ALL,
    "nudr-dr": _ALL, "nausf-auth": {"POST", "PUT", "DELETE"},
    "nsmf-pdusession": _ALL, "nsmf-event-exposure": _ALL,
    "namf-comm": _ALL, "namf-evts": _ALL, "namf-mt": _ALL, "namf-loc": _ALL,
    "npcf-am-policy-control": _ALL, "npcf-smpolicycontrol": _ALL, "npcf-policyauthorization": _ALL,
    "npcf-bdtpolicycontrol": _ALL, "npcf-eventexposure": _ALL,
    "nnssf-nsselection": {"GET"}, "nnssf-nssaiavailability": _ALL,
    "nbsf-management": _ALL, "nnwdaf-eventssubscription": _ALL, "nnwdaf-analyticsinfo": {"GET", "POST"},
}
CALLER_FORBIDDEN = {      # caller NF -> service prefixes it never legitimately calls
    "AMF": ["nudm-ueau", "nudr-dr"], "SMF": ["nausf-auth", "nudm-ueau", "nudr-dr"],
    "PCF": ["nudm-ueau", "nausf-auth"], "AUSF": ["nudr-dr", "nsmf-", "npcf-"],
    "NSSF": ["nudm-", "nausf-", "nsmf-", "npcf-", "nudr-dr"], "BSF": ["nudm-", "nausf-", "nsmf-", "nudr-dr"],
}
SINGLETON_TYPES = set(os.environ.get("IDRS_SINGLETON_NFS", "AMF,SMF,UDM,UDR,AUSF,PCF,NSSF,NRF,BSF,SCP").split(","))
NF_PUT = re.compile(r"^/nnrf-nfm/v\d+/nf-instances/([^/?]+)$")
SMCTX = re.compile(r"^/nsmf-pdusession/v\d+/sm-contexts(?:/([^/?]+))?(?:/(modify|release|retrieve))?")
SMCTX_LOC = re.compile(r"/nsmf-pdusession/v\d+/sm-contexts/([^/?]+)")
POL_LOC = re.compile(r"/npcf-[a-z-]+/v\d+/(?:sm-policies|policies)/([^/?]+)")
POL_PATH = re.compile(r"^/npcf-[a-z-]+/v\d+/(?:sm-policies|policies)/([^/?]+)(?:/(update|delete))?")


class ThreatEngine:
    BASE = {"T01": 70, "T02": 85, "T03": 80, "T04": 75, "T05": 65, "T06": 60, "T07": 55, "T08": 90,
            "T09": 80, "T10": 70, "X01": 65, "X02": 65, "X03": 75}
    RECENCY_TAU, RECENCY_FRESH = 30.0, 5.0
    W_SHORT, W_MID, W_LONG = 10.0, 30.0, 60.0
    FIRE_COOLDOWN = 10.0
    ACTIVE_TTL, ACTIVE_MAX = 600.0, 500

    # thresholds (runtime-adjustable through set_thresholds)
    T01_THRESH = 20            # NF registrations (PUT) / 10 s
    T05_READS, T05_DISTINCT = 300, 40       # UDM profile reads / distinct SUPIs per NF in 30 s
    T06_K, T06_FLOOR, T06_WARMUP = 5.0, 15.0, 60.0    # x baseline, min pps, warm-up seconds
    T06_FLOOR_SBI = 30.0       # SBI is dense (about 25 events per UE attach): own floor, counts REQUESTS only
    T08_GRACE = 60.0           # a duplicate singleton NF must persist this long (stale entry after a crash expires)
    T10_THRESH = 30            # PCF modifications / 10 s per caller
    X01_THRESH = 5             # NAS failures / 10 s
    X02_THRESH = 5             # Identity Requests / 10 s
    WARMUP = float(os.environ.get("IDRS_WARMUP_SEC", "120"))      # T02/T03/T09/T10 state rules

    CORE_IP = os.environ.get("IDRS_CORE_IP", "192.168.56.10")
    UPF_IP = os.environ.get("IDRS_UPF_IP", "192.168.56.20")
    THRESHOLD_KEYS = ("T01_THRESH", "T05_READS", "T05_DISTINCT", "T06_K", "T06_FLOOR", "T06_FLOOR_SBI",
                      "T06_WARMUP", "T08_GRACE", "T10_THRESH", "X01_THRESH", "X02_THRESH", "WARMUP", "FIRE_COOLDOWN")
    # T09 needs the GTP-U sensor on the UPF VM (and an authenticated Redis); off until enabled
    DISABLED_DEFAULT = [r for r in os.environ.get("IDRS_DISABLE_RULES", "T09").replace(" ", "").split(",") if r]
    RULE_PRIMARY = {"T01": "T01_THRESH", "T05": "T05_READS", "T06": "T06_FLOOR", "T10": "T10_THRESH",
                    "X01": "X01_THRESH", "X02": "X02_THRESH"}

    def __init__(self, alert_callback: Callable[[ThreatEvent], None] = None):
        self.alert_callback = alert_callback or (lambda t: None)
        self._mx = threading.RLock()
        self._short, self._mid, self._long = (WindowRegistry(self.W_SHORT), WindowRegistry(self.W_MID),
                                              WindowRegistry(self.W_LONG))
        self._pps: Dict[str, dict] = {}
        self._flood_flags: Dict[str, Tuple[float, float]] = {}
        self._reg_ids: Deque[Tuple[float, str]] = deque(maxlen=500)
        self._udm: Dict[str, Deque[Tuple[float, str]]] = defaultdict(deque)
        self._seids: Dict[str, float] = {}
        self._ul_teids: Dict[int, float] = {}
        self._smctx: set = set()
        self._policies: set = set()
        self._ident_gnbs: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._bind: Dict[Tuple[str, int], str] = {}
        self._anoms: Dict[str, Dict[str, float]] = defaultdict(dict)
        self._registry: Dict[str, Tuple[str, float]] = {}
        self._first_ts: Optional[float] = None
        self._last_fire: Dict[Tuple[str, str], float] = {}
        self._active: Dict[str, ThreatEvent] = {}
        self._evaluated = self._fired = 0
        self.disabled = set(self.DISABLED_DEFAULT)
        self.persist: Optional[Callable[[str, str, float], None]] = None     # (kind, key, ts) -> durable store
        self._conflicts: Dict[str, Tuple[float, frozenset]] = {}
        self._rules = {"T01": self._t01, "T02": self._t02, "T03": self._t03, "T04": self._t04, "T05": self._t05,
                       "T06": self._t06, "T07": self._t07, "T09": self._t09, "T10": self._t10,
                       "X01": self._x01, "X02": self._x02, "X03": self._x03}

    # ------------------------------------------------------------------ public
    def evaluate(self, e: IDRSEvent, now: float = None) -> Optional[ThreatEvent]:
        with self._mx:
            now = time.time() if now is None else now
            self._evaluated += 1
            if self._first_ts is None:
                self._first_ts = e.timestamp
                self._save("meta", "first_ts", e.timestamp)
            self._enrich(e)
            self._learn(e)
            found = [t for rid, fn in self._rules.items() if rid not in self.disabled
                     for t in [fn(e, now)] if t]
            fired = None
            for t in sorted(found, key=lambda x: x.score, reverse=True):
                if self._register(t):
                    fired = fired or t
            return fired

    # ---------------------------------------------------- durable learned state
    def _save(self, kind, key, ts):
        if self.persist:
            try:
                self.persist(kind, str(key), ts)
            except Exception:
                pass

    def restore_state(self, rows):
        """rows: (kind, key, ts). Sessions/policies/identities that predate a restart must not look unknown."""
        with self._mx:
            for kind, key, ts in rows:
                if kind == "seid":
                    self._seids[key] = ts
                elif kind == "ul_teid":
                    self._ul_teids[int(key)] = ts
                elif kind == "smctx":
                    self._smctx.add(key)
                elif kind == "policy":
                    self._policies.add(key)
                elif kind == "meta" and key == "first_ts":
                    self._first_ts = ts

    def learn_only(self, e: IDRSEvent):
        """Absorb an event into the learned state WITHOUT evaluating any rule (history replay at start-up)."""
        with self._mx:
            if self._first_ts is None:
                self._first_ts = e.timestamp
                self._save("meta", "first_ts", e.timestamp)
            self._enrich(e)
            self._learn(e)

    def rules_state(self) -> dict:
        ids = sorted(list(self._rules) + ["T08"])
        return {r: (r not in self.disabled) for r in ids}

    def set_rule_enabled(self, rule: str, enabled: bool) -> dict:
        rule = rule.upper()
        if rule not in self.rules_state():
            raise ValueError(f"unknown rule {rule}")
        (self.disabled.discard if enabled else self.disabled.add)(rule)
        return self.rules_state()

    def pps_stats(self) -> dict:
        """Per-interface observed rate: use it to choose T06 floors (peak during normal operation x ~1.5)."""
        out = {}
        for iface, st in self._pps.items():
            out[iface] = {"baseline_pps": round(st["ewma"] or 0.0, 2), "peak_pps": round(st.get("peak", 0.0), 1),
                          "floor_pps": self._floor(iface), "threshold_pps": round(self._t06_threshold(st, iface), 1),
                          "seconds_observed": st["secs"]}
        return out

    def ingest_registry(self, snapshot: Dict[str, dict], now: float = None) -> List[ThreatEvent]:
        """T08 Rogue NF: NF-type conflicts in the NRF registry.
        * a duplicate singleton NF must PERSIST for T08_GRACE seconds: after a crash/kill the stale entry
          lingers until the NRF expires it, and the restarted NF must not be flagged as the rogue one;
        * the earliest registration is treated as legitimate; if the two earliest are indistinguishable
          (baseline snapshot) the alert is raised without instance ids, so nothing can be auto-deleted."""
        with self._mx:
            now = time.time() if now is None else now
            prev, first, cur, out = self._registry, not self._registry, {}, []
            for nid, prof in snapshot.items():
                typ = prof.get("nfType")
                cur[nid] = (typ, prev[nid][1] if nid in prev else (0.0 if first else now))
                if nid in prev and prev[nid][0] != typ and "T08" not in self.disabled:
                    out.append(self._t08_threat(now, [nid], typ, f"nfType changed {prev[nid][0]} -> {typ}", snapshot))
            by_type = defaultdict(list)
            for nid, (typ, ts0) in cur.items():
                by_type[typ].append((ts0, nid))
            conflicts = {}
            for typ, lst in by_type.items():
                if typ not in SINGLETON_TYPES or len(lst) < 2:
                    continue
                lst.sort()
                members = frozenset(n for _, n in lst)
                old = self._conflicts.get(typ)
                since = old[0] if old and old[1] == members else now
                conflicts[typ] = (since, members)
                if "T08" in self.disabled or now - since < self.T08_GRACE:
                    continue
                ambiguous = lst[0][0] == lst[1][0]
                rogue = [] if ambiguous else [n for _, n in lst][1:]
                th = self._t08_threat(now, rogue or [lst[1][1]], typ,
                                      f"second {typ} instance persisted for {int(now - since)} s", snapshot)
                th.evidence.update({"ambiguous": ambiguous, "instances": [n for _, n in lst]})
                if ambiguous:
                    th.evidence["nf_instance_ids"] = []          # notify only: never auto-delete a guess
                out.append(th)
            self._conflicts = conflicts
            self._registry = cur
            return [t for t in out if self._register(t)]

    def get_thresholds(self) -> dict:
        return {k: getattr(self, k) for k in self.THRESHOLD_KEYS}

    def set_thresholds(self, new: dict) -> dict:
        for k, v in new.items():
            if k not in self.THRESHOLD_KEYS:
                raise ValueError(f"unknown threshold {k}")
            if not isinstance(v, (int, float)) or isinstance(v, bool) or v <= 0:
                raise ValueError(f"{k} must be a positive number")
        for k, v in new.items():
            setattr(self, k, v)
        return self.get_thresholds()

    def set_rule_threshold(self, rule_id: str, value) -> dict:
        key = self.RULE_PRIMARY.get(rule_id.upper())
        if not key:
            raise ValueError(f"rule {rule_id} has no single numeric threshold (see /config/thresholds)")
        return self.set_thresholds({key: value})

    def get_active(self) -> List[ThreatEvent]:
        now = time.time()
        with self._mx:
            for tid in [k for k, t in self._active.items() if now - t.detected_at > self.ACTIVE_TTL]:
                del self._active[tid]
            return list(self._active.values())

    def clear(self, threat_id: str) -> bool:
        with self._mx:
            return self._active.pop(threat_id, None) is not None

    def stats(self) -> dict:
        return {"evaluated": self._evaluated, "fired": self._fired, "active": len(self._active)}

    # ---------------------------------------------------------------- scoring
    def _score(self, rule, age, count, ref, corro):
        base = self.BASE[rule]
        late = max(age - self.RECENCY_FRESH, 0.0)          # live detections (<= grace) keep full weight
        w_rec = 0.5 + 0.5 * math.exp(-late / self.RECENCY_TAU)
        w_freq = 1.0 + min(1.0, max(0.0, count / ref - 1.0)) if ref else 1.0
        w_freq = min(2.0, w_freq + 0.25 * corro)
        return round(min(100.0, base * w_rec * w_freq), 1), {"base": base, "w_recency": round(w_rec, 3),
                                                              "w_frequency": round(w_freq, 3)}

    def _corro(self, key: Optional[str], iface: str, now: float) -> int:
        """Cross-interface temporal correlation: other interfaces with an anomaly for this identity <= 60 s ago."""
        if not key:
            return 0
        d = self._anoms[key]
        n = sum(1 for i, t in d.items() if i != iface and now - t <= self.W_LONG)
        d[iface] = now
        if len(self._anoms) > 5000:
            self._anoms.clear()
        return n

    def _make(self, rule, name, cat, ctx, now, count, ref, evidence, dedup=None):
        key = ctx.supi or (ctx.src_ip if ctx.src_ip and not ctx.src_ip.startswith("127.") else None)
        score, parts = self._score(rule, now - ctx.timestamp, count, ref, self._corro(key, ctx.interface, now))
        t = ThreatEvent(rule_id=rule, rule_name=name, category=cat, score=score, severity=score_to_severity(score),
                        supi=ctx.supi, src_ip=ctx.src_ip, interface=ctx.interface, parser=ctx.parser,
                        trigger_msg=ctx.msg_type, evidence={**evidence, "score_parts": parts},
                        detected_at=ctx.timestamp)
        t._dedup = dedup
        return t

    def _register(self, t: ThreatEvent) -> bool:
        key = (t.rule_id, getattr(t, "_dedup", None) or t.supi or t.src_ip or "global")
        last = self._last_fire.get(key)
        if last is not None and t.detected_at - last < self.FIRE_COOLDOWN:
            return False
        self._last_fire[key] = t.detected_at
        if len(self._last_fire) > 5000:
            self._last_fire.clear()
        if len(self._active) >= self.ACTIVE_MAX:
            oldest = min(self._active.values(), key=lambda x: x.detected_at)
            self._active.pop(oldest.threat_id, None)
        self._active[t.threat_id] = t
        self._fired += 1
        self.alert_callback(t)
        return True

    # --------------------------------------------------------- enrich / learn
    def _gnb_of(self, e):
        return e.dst_ip if e.src_ip == self.CORE_IP else e.src_ip

    def _enrich(self, e):
        ran = e.fields.get("ran_ue_ngap_id")
        if ran is None or e.parser not in ("nas", "ngap"):
            return
        k = (self._gnb_of(e) or "?", ran)
        if e.parser == "nas" and e.supi:
            if len(self._bind) > 5000:
                self._bind.clear()
            self._bind[k] = e.supi
        elif e.parser == "ngap" and not e.supi:
            e.supi = self._bind.get(k)         # subscriber identity for later NGAP events of the same UE

    def _learn(self, e):
        f = e.fields
        if e.parser == "pfcp" and e.msg_type == "Session Establishment Response":
            if f.get("fseid"):
                self._seids[f["fseid"]] = e.timestamp
                self._save("seid", f["fseid"], e.timestamp)
            for t in f.get("ul_teids") or []:
                self._ul_teids[t] = e.timestamp
                self._save("ul_teid", t, e.timestamp)
            for d in (self._seids, self._ul_teids):
                if len(d) > 10000:
                    d.clear()
        loc = f.get("location") or ""
        if loc:
            m = SMCTX_LOC.search(loc)
            if m and m.group(1) not in self._smctx:
                self._smctx.add(m.group(1))
                self._save("smctx", m.group(1), e.timestamp)
            m = POL_LOC.search(loc)
            if m and m.group(1) not in self._policies:
                self._policies.add(m.group(1))
                self._save("policy", m.group(1), e.timestamp)
            for st in (self._smctx, self._policies):
                if len(st) > 20000:
                    st.clear()

    def _warm(self, e) -> bool:
        return e.timestamp - (self._first_ts or e.timestamp) >= self.WARMUP

    @staticmethod
    def _sbi(e):
        if e.parser != "sbi_http2" or not e.fields.get("method") or not e.fields.get("path"):
            return None
        return e.fields["method"], e.fields["path"].split("?")[0], caller_nf_from(e.fields)

    # ------------------------------------------------------------------ rules
    def _t01(self, e, now):
        s = self._sbi(e)
        if not s or s[0] != "PUT" or s[2] == "SCP":
            return None
        m = NF_PUT.match(s[1])
        if not m:
            return None
        self._reg_ids.append((e.timestamp, m.group(1)))
        n = self._short.hit("T01", "nrf", e.timestamp)
        if n < self.T01_THRESH:
            return None
        # Only instances NOT already established in the NRF registry may be rejected by the mitigator
        # (legitimate NFs re-registering during the window must never be touched). No registry = no ids.
        ids = sorted({i for ts, i in self._reg_ids
                      if e.timestamp - ts <= self.W_SHORT and self._registry
                      and (i not in self._registry or e.timestamp - self._registry[i][1] < self.W_MID)})[:50]
        return self._make("T01", "NF Registration Flood", C.ROGUE_NF, e, now, n, self.T01_THRESH,
                          {"registrations_in_10s": n, "threshold": self.T01_THRESH, "nf_instance_ids": ids},
                          dedup="nrf")

    def _t02(self, e, now):
        s = self._sbi(e)
        if not s or s[2] == "SCP":
            return None
        m = SMCTX.match(s[1])
        if not m:
            return None
        why = None
        if s[2] and s[2] != "AMF":
            why = f"SM-context request issued by {s[2]} (only the AMF may)"
        elif m.group(1) and self._smctx and self._warm(e) and m.group(1) not in self._smctx:
            why = f"smContextRef {m.group(1)} was never created through this SBI"
        if not why:
            return None
        n = self._long.hit("T02", s[2] or "?", e.timestamp)
        return self._make("T02", "Session Hijack (SM-context from unexpected NF)", C.SESSION_MANIPULATION, e, now,
                          n, 5, {"reason": why, "caller": s[2], "path": s[1]}, dedup=s[2] or "?")

    def _t03(self, e, now):
        if e.parser != "pfcp" or e.msg_type not in ("Session Modification Request", "Session Deletion Request"):
            return None
        sid = e.session_id
        if not sid or sid == "0" or not self._warm(e):
            return None
        seen = self._seids.get(sid)
        if seen is not None:
            return None
        n = self._long.hit("T03", e.src_ip or "?", e.timestamp)
        return self._make("T03", "PFCP Session Manipulation (Modify/Delete without Establish)",
                          C.SESSION_MANIPULATION, e, now, n, 5,
                          {"seid": sid, "known_seids": len(self._seids), "note": "SEID never announced in an Establishment Response"})

    def _t04(self, e, now):
        if e.parser != "nas" or e.msg_type != "Registration Request" or not e.supi:
            return None
        gnb = self._gnb_of(e)
        d = self._ident_gnbs[e.supi]
        d[gnb] = e.timestamp
        for g in [g for g, t in d.items() if e.timestamp - t > self.W_LONG]:
            del d[g]
        if len(self._ident_gnbs) > 5000:
            self._ident_gnbs.clear()
        if len(d) < 2:
            return None
        return self._make("T04", "Registration Abuse (same IMSI via different gNBs)", C.AUTH_ABUSE, e, now,
                          len(d), 2, {"gnbs": sorted(d), "window_sec": self.W_LONG})

    def _t05(self, e, now):
        s = self._sbi(e)
        if not s or s[0] != "GET" or s[2] == "SCP":
            return None
        if not (s[1].startswith("/nudm-sdm") or s[1].startswith("/nudm-uecm")):
            return None
        key = s[2] or e.src_ip or "?"
        q = self._udm[key]
        q.append((e.timestamp, e.supi or ""))
        while q and q[0][0] < e.timestamp - self.W_MID:
            q.popleft()
        reads, distinct = len(q), len({x for _, x in q if x})
        if reads < self.T05_READS and distinct < self.T05_DISTINCT:
            return None
        ratio = max(reads / self.T05_READS, distinct / self.T05_DISTINCT)
        t = self._make("T05", "UDM Exfiltration (bulk subscriber-profile reads)", C.DATA_EXFILTRATION, e, now,
                       ratio, 1, {"reads_in_30s": reads, "distinct_supis_in_30s": distinct, "caller": key}, dedup=key)
        t.supi = None
        return t

    def _t06(self, e, now):
        iface, w = e.interface, int(e.fields.get("count") or 1)
        if e.parser == "sbi_http2" and (not e.fields.get("method") or caller_nf_from(e.fields) == "SCP"):
            return None          # SBI rate = requests only: responses and the SCP second hop mirror them
        st = self._pps.setdefault(iface, {"sec": None, "cur": 0, "hist": deque(maxlen=4), "ewma": None,
                                          "secs": 0, "srcs": defaultdict(int)})
        s = int(e.timestamp)
        if st["sec"] is None:
            st["sec"] = s
        if s > st["sec"]:
            for c in [st["cur"]] + [0] * (min(s - st["sec"], 10) - 1):
                st["hist"].append(c)
                thr_now = self._t06_threshold(st, iface)
                if st["ewma"] is None:
                    st["ewma"] = float(c)
                elif c < thr_now:                       # anomalous seconds never pollute the baseline
                    st["ewma"] = 0.95 * st["ewma"] + 0.05 * c
                st["secs"] += 1
            st["sec"], st["cur"] = s, 0
            st["srcs"].clear()
        st["cur"] += w
        st["srcs"][e.src_ip] += w
        rate = (sum(st["hist"]) + st["cur"]) / 5.0
        st["peak"] = max(st.get("peak", 0.0), rate)
        thr = self._t06_threshold(st, iface)
        if rate < thr:
            return None
        self._flood_flags[iface] = (e.timestamp, rate)
        top = max(st["srcs"], key=st["srcs"].get)
        return self._make("T06", "Signalling Flood (PPS above baseline)", C.SIGNALLING_FLOOD, e, now, rate, thr,
                          {"interface": iface, "rate_pps": round(rate, 1), "baseline_pps": round(st["ewma"] or 0, 2),
                           "threshold_pps": round(thr, 1), "top_source": top}, dedup=iface)

    def _floor(self, iface):
        return self.T06_FLOOR_SBI if iface == "SBI" else self.T06_FLOOR

    def _t06_threshold(self, st, iface):
        base = st["ewma"] if (st["ewma"] is not None and st["secs"] >= self.T06_WARMUP) else 0.0
        return max(self._floor(iface), self.T06_K * base)

    def _t07(self, e, now):
        s = self._sbi(e)
        if not s or s[2] == "SCP":
            return None
        method, path, caller = s
        parts = path.split("/")
        svc = parts[1] if len(parts) > 1 else ""
        why = None
        if svc.endswith("-callback"):
            return None
        if svc not in KNOWN_SERVICES:
            why = f"service '{svc}' is not a 3GPP SBI service"
        elif method not in KNOWN_SERVICES[svc]:
            why = f"{method} is not a defined operation of {svc}"
        elif caller and any(svc.startswith(p) for p in CALLER_FORBIDDEN.get(caller, [])):
            why = f"{caller} does not consume {svc}"
        if not why:
            return None
        n = self._long.hit("T07", caller or e.src_ip or "?", e.timestamp)
        return self._make("T07", "Unauthorized API call", C.UNAUTHORIZED_API, e, now, n, 5,
                          {"reason": why, "method": method, "path": path, "caller": caller},
                          dedup=f"{caller or e.src_ip}:{svc}")

    def _t08_threat(self, now, ids, typ, why, snapshot):
        prof = snapshot.get(ids[0], {})
        ctx = SimpleNamespace(supi=None, src_ip=(prof.get("ipv4Addresses") or [None])[0], interface="SBI",
                              parser="nrf_registry", msg_type="NRF registry poll", timestamp=now)
        return self._make("T08", "Rogue NF (type conflicts with NRF registry)", C.ROGUE_NF, ctx, now, len(ids), 1,
                          {"reason": why, "nf_type": typ, "nf_instance_ids": ids,
                           "ipv4": prof.get("ipv4Addresses")}, dedup=ids[0])

    def _t09(self, e, now):
        if e.parser != "gtpu" or e.msg_type != "G-PDU" or e.dst_ip != self.UPF_IP:
            return None
        teid = e.fields.get("teid")
        if teid is None or not self._ul_teids or not self._warm(e) or teid in self._ul_teids:
            return None
        n = int(e.fields.get("count") or 1)
        return self._make("T09", "GTP Abuse (TEID without control-plane session)", C.TUNNEL_ABUSE, e, now, n, 10,
                          {"teid": teid, "packets": n, "known_ul_teids": len(self._ul_teids)}, dedup=str(teid))

    def _t10(self, e, now):
        s = self._sbi(e)
        if not s or s[2] == "SCP" or not s[1].startswith("/npcf-"):
            return None
        method, path, caller = s
        m = POL_PATH.match(path)
        modifying = method in ("PUT", "PATCH", "DELETE") or (m and m.group(2) in ("update", "delete"))
        if not modifying:
            return None
        key = caller or e.src_ip or "?"
        n = self._short.hit("T10", key, e.timestamp)
        why = None
        if m and self._policies and self._warm(e) and m.group(1) not in self._policies:
            why = f"policy {m.group(1)} was never created through this SBI"
        elif n >= self.T10_THRESH:
            why = f"{n} policy modifications in 10 s"
        if not why:
            return None
        return self._make("T10", "PCF Tampering", C.POLICY_TAMPERING, e, now, max(n, 1), self.T10_THRESH,
                          {"reason": why, "path": path, "method": method, "caller": caller}, dedup=key)

    def _x01(self, e, now):
        if e.parser != "nas" or not any(m in e.msg_type for m in (
                "Authentication Failure", "Authentication Reject", "Security Mode Reject", "Registration Reject")):
            return None
        n = self._short.hit("X01", e.src_ip or "?", e.timestamp)
        if n < self.X01_THRESH:
            return None
        return self._make("X01", "NAS Authentication/Security Failure Burst", C.AUTH_ABUSE, e, now, n,
                          self.X01_THRESH, {"failures_in_10s": n, "last": e.msg_type})

    def _x02(self, e, now):
        if e.parser != "nas" or "Identity Request" not in e.msg_type:
            return None
        n = self._short.hit("X02", e.src_ip or "?", e.timestamp)
        if n < self.X02_THRESH:
            return None
        return self._make("X02", "NAS Identity Request Flood", C.AUTH_ABUSE, e, now, n, self.X02_THRESH,
                          {"identity_requests_in_10s": n})

    def _x03(self, e, now):
        live = {i: r for i, (t, r) in self._flood_flags.items() if e.timestamp - t <= self.W_MID}
        if len(live) < 2:
            return None
        return self._make("X03", "Coordinated multi-interface flood", C.CROSS_INTERFACE, e, now, len(live), 2,
                          {"interfaces": {i: round(r, 1) for i, r in live.items()}, "window_sec": self.W_MID},
                          dedup="global")
