"""
nwdaf/live.py -- real-time feed behind the web dashboard.

Everything pushed here comes from the running pipeline (parsers -> Redis -> NWDAF ->
engine -> alert manager -> mitigator). Nothing is generated or simulated.

Feed item kinds:  event | alert | mitigation | tick
  * event       a parsed control-plane message (rate-limited so a flood cannot swamp the browser;
                the per-second tick always carries the TRUE per-interface counts)
  * alert       a detection plus what the Alert Manager did with it
  * mitigation  one Mitigator record
  * tick        1 Hz snapshot: per-interface rates, ingest latency, counters, parser liveness
Events older than FRESH_SEC are history being replayed from Redis at start-up; they are counted
as `replayed` and excluded from rates/latency so the dashboard never shows old traffic as live.
"""
import threading
import time
import uuid
from collections import defaultdict, deque
from typing import Any, Dict, List, Tuple

FRESH_SEC = 30.0
DROP_KEYS = {"raw_hex", "_nas_pdu_bytes"}


def compact_event(e) -> dict:
    fields = {}
    for k, v in (e.fields or {}).items():
        if k in DROP_KEYS:
            fields[k + "_len"] = len(v) // 2 if isinstance(v, str) else None
        else:
            fields[k] = v
    return {"event_id": e.event_id, "timestamp": e.timestamp, "parser": e.parser,
            "interface": e.interface, "msg_type": e.msg_type, "src_ip": e.src_ip,
            "dst_ip": e.dst_ip, "supi": e.supi, "session_id": e.session_id, "fields": fields}


class LiveFeed:
    def __init__(self, maxlen: int = 3000, max_events_per_sec: int = 40):
        self.boot_id = uuid.uuid4().hex[:8]
        self.max_eps = max_events_per_sec
        self._items: deque = deque(maxlen=maxlen)
        self._seq = 0
        self._lock = threading.Lock()
        self._tick_counts: Dict[str, int] = defaultdict(int)
        self._lat: List[float] = []
        self._fed_sec = 0
        self._dropped_sec = 0
        self.dropped_total = 0
        self.replayed_total = 0
        self.parser_last_seen: Dict[str, float] = {}

    # -- feed primitives ---------------------------------------------------
    @property
    def seq(self) -> int:
        return self._seq

    def push(self, kind: str, payload: Any) -> int:
        with self._lock:
            self._seq += 1
            self._items.append((self._seq, kind, payload))
            return self._seq

    def after(self, seq: int) -> List[Tuple[int, str, Any]]:
        with self._lock:
            return [it for it in self._items if it[0] > seq]

    # -- pipeline hooks ------------------------------------------------------
    def observe_event(self, e, now: float = None):
        now = now or time.time()
        age = now - e.timestamp
        if age > FRESH_SEC:
            self.replayed_total += 1
            return
        with self._lock:
            self.parser_last_seen[e.parser] = now
            self._tick_counts[e.interface] += 1
            self._lat.append(max(age, 0.0) * 1000.0)
            send = self._fed_sec < self.max_eps
            if send:
                self._fed_sec += 1
            else:
                self._dropped_sec += 1
                self.dropped_total += 1
        if send:
            self.push("event", compact_event(e))

    def drain_tick(self) -> dict:
        with self._lock:
            rate = dict(self._tick_counts)
            lat = self._lat
            out = {
                "rate": rate,
                "lat_avg_ms": round(sum(lat) / len(lat), 2) if lat else None,
                "lat_max_ms": round(max(lat), 2) if lat else None,
                "feed_dropped_sec": self._dropped_sec,
                "feed_dropped_total": self.dropped_total,
                "replayed_total": self.replayed_total,
            }
            self._tick_counts = defaultdict(int)
            self._lat = []
            self._fed_sec = 0
            self._dropped_sec = 0
            seen = dict(self.parser_last_seen)
        now = time.time()
        out["parser_age_sec"] = {p: round(now - t, 1) for p, t in seen.items()}
        return out
