"""
Custom NWDAF microservice (§3.4.1).

Open5GS has no built-in NWDAF, so this service plays that architectural
role for the IDRS: it is the single coordination point that consumes
every parser's events off `ids:events`, holds a short rolling window of
recent events and per-interface/per-parser counters, and exposes that
state over a REST API loosely modeled on the real Nnwdaf_AnalyticsInfo
service (TS 29.520) -- enough for a human (or, in Phase 2, the Threat
Evaluation Engine) to query "what has this core seen recently".

This is intentionally NOT the Threat Evaluation Engine -- there is no
scoring or rule evaluation here, only collection and summarisation.
That keeps this service aligned with the NWDAF's real 3GPP role
(analytics/telemetry coordination), with detection logic staying a
separate module as designed in Chapter 3.
"""
import os
import threading
import time
from collections import deque, defaultdict
from typing import Optional

from fastapi import FastAPI
import uvicorn

from common.events import IDRSEvent
from common.redis_client import get_redis, EVENTS_STREAM

MAX_RECENT_EVENTS = int(os.environ.get("NWDAF_RECENT_BUFFER", "2000"))

app = FastAPI(title="Custom NWDAF (IDRS coordination point)", version="0.1.0")

_lock = threading.Lock()
_recent_events: deque = deque(maxlen=MAX_RECENT_EVENTS)
_counts_by_parser = defaultdict(int)
_counts_by_interface = defaultdict(int)
_start_time = time.time()


def _consume_loop():
    r = get_redis()
    last_id = "0"
    print("[NWDAF] consumer thread started, reading ids:events", flush=True)
    while True:
        try:
            resp = r.xread({EVENTS_STREAM: last_id}, block=5000, count=100)
        except Exception as e:
            print(f"[NWDAF] redis read error: {e}", flush=True)
            time.sleep(2)
            continue
        if not resp:
            continue
        for _stream, messages in resp:
            for msg_id, fields in messages:
                last_id = msg_id
                raw = fields.get("data")
                if not raw:
                    continue
                try:
                    event = IDRSEvent.from_json(raw)
                except Exception:
                    continue
                with _lock:
                    _recent_events.append(event)
                    _counts_by_parser[event.parser] += 1
                    _counts_by_interface[event.interface] += 1


@app.on_event("startup")
def start_consumer():
    t = threading.Thread(target=_consume_loop, daemon=True)
    t.start()


@app.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": round(time.time() - _start_time, 1)}


@app.get("/stats")
def stats():
    with _lock:
        return {
            "total_events_seen": sum(_counts_by_parser.values()),
            "by_parser": dict(_counts_by_parser),
            "by_interface": dict(_counts_by_interface),
            "buffer_size": len(_recent_events),
        }


@app.get("/events/recent")
def recent_events(limit: int = 50, parser: Optional[str] = None, supi: Optional[str] = None):
    with _lock:
        items = list(_recent_events)
    if parser:
        items = [e for e in items if e.parser == parser]
    if supi:
        items = [e for e in items if e.supi == supi]
    items = items[-limit:]
    return [
        {
            "event_id": e.event_id, "timestamp": e.timestamp, "parser": e.parser,
            "interface": e.interface, "msg_type": e.msg_type, "src_ip": e.src_ip,
            "dst_ip": e.dst_ip, "supi": e.supi, "session_id": e.session_id, "fields": e.fields,
        }
        for e in items
    ]


@app.get("/nnwdaf-analyticsinfo/v1/summary")
def analytics_summary():
    """Loosely modeled on Nnwdaf_AnalyticsInfo_Request (TS 29.520) --
    a coarse point-in-time summary a consumer (e.g. the future Threat
    Evaluation Engine, or PCF/SMF) could subscribe-and-poll against."""
    with _lock:
        window = list(_recent_events)[-200:]
    if not window:
        return {"analytics": "no data yet"}
    span = window[-1].timestamp - window[0].timestamp if len(window) > 1 else 1
    rate = len(window) / span if span > 0 else 0
    return {
        "sample_size": len(window),
        "approx_events_per_second": round(rate, 2),
        "distinct_supis_seen": len({e.supi for e in window if e.supi}),
        "by_interface": {
            iface: sum(1 for e in window if e.interface == iface)
            for iface in {e.interface for e in window}
        },
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("NWDAF_PORT", "8090")))
