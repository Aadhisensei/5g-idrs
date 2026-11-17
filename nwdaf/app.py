"""
nwdaf/app.py — IDRS Custom NWDAF (All Phases)

Phase 1 — Event buffer, stats, /events/recent
Phase 2 — Threat Engine (T01-T10), /threats/*
Phase 3 — Tiered Alert Manager, /alerts/*
Phase 4 — Attack Mitigation Module, /mitigation/*
"""
import asyncio
import hmac
import json
import os
import secrets
import threading
import time
from urllib.parse import parse_qs
from collections import deque, defaultdict
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
import uvicorn

from common.events       import IDRSEvent
from common.redis_client import get_redis, EVENTS_STREAM
from nwdaf.threat_engine import ThreatEngine
from nwdaf.threat_models import ThreatEvent
from nwdaf.alert_manager import AlertManager, Alert
from nwdaf.live          import LiveFeed, compact_event
from nwdaf.store         import Store
from nwdaf.nrf_registry  import RegistryPoller
try:                                    # Phase 4 module; app still runs (detection-only) without it
    from nwdaf.mitigator import Mitigator, MitigationRecord, initial_mode_from_env
except ImportError:
    Mitigator = None

MAX_RECENT_EVENTS  = int(os.environ.get("NWDAF_RECENT_BUFFER", "2000"))
MAX_RECENT_THREATS = int(os.environ.get("NWDAF_THREAT_BUFFER",  "500"))

# Control-plane token: required (X-API-Token header) for every state-changing endpoint.
# Set IDRS_API_TOKEN, or one is generated and printed in the NWDAF log at start-up.
API_TOKEN = os.environ.get("IDRS_API_TOKEN") or secrets.token_urlsafe(12)
TOKEN_GENERATED = not os.environ.get("IDRS_API_TOKEN")


PROTECT_READS = os.environ.get("IDRS_PROTECT_READS", "true").lower() != "false"
OPEN_PATHS = {"/", "/ui", "/health", "/docs", "/redoc", "/openapi.json"}   # page shell + liveness only; no data


def _token_ok(given: str) -> bool:
    return bool(given) and hmac.compare_digest(given.encode(), API_TOKEN.encode())


def require_token(request: Request):
    given = request.headers.get("x-api-token") or request.query_params.get("token", "")
    if not _token_ok(given):
        raise HTTPException(401, "missing or invalid X-API-Token")


class AuthMiddleware:
    """Pure ASGI (safe for SSE). State-changing requests always need the token; reads need it too
    unless IDRS_PROTECT_READS=false. EventSource cannot set headers, so ?token= is accepted."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http" and scope["path"] not in OPEN_PATHS and (
                scope["method"] not in ("GET", "HEAD", "OPTIONS") or PROTECT_READS):
            given = dict(scope["headers"]).get(b"x-api-token", b"").decode()
            if not given:
                given = (parse_qs(scope["query_string"].decode()).get("token") or [""])[0]
            if not _token_ok(given):
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"application/json")]})
                await send({"type": "http.response.body", "body": b'{"detail":"missing or invalid X-API-Token"}'})
                return
        await self.app(scope, receive, send)


# SQLite persistence (alerts + mitigation log survive restarts). Optional: runs without if unwritable.
try:
    _store = Store()
except Exception as _exc:
    print(f"[NWDAF] persistence disabled ({_exc})", flush=True)
    _store = None

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app):
    start_consumer()
    announce_token()
    yield


app = FastAPI(
    title   = "IDRS NWDAF — Full IDS Pipeline",
    version = "0.5.0",
    lifespan = lifespan,
)
app.add_middleware(AuthMiddleware)

# ------------------------------------------------------------------
# Shared state
# ------------------------------------------------------------------
_lock = threading.Lock()

_recent_events:  deque = deque(maxlen=MAX_RECENT_EVENTS)
_recent_threats: deque = deque(maxlen=MAX_RECENT_THREATS)

_counts_by_parser    = defaultdict(int)
_counts_by_interface = defaultdict(int)
_counts_by_rule      = defaultdict(int)

_start_time = time.time()

# ------------------------------------------------------------------
# Phase 4: Mitigation Module
# ------------------------------------------------------------------
_mitigator = Mitigator(mode=initial_mode_from_env(), store=_store) if Mitigator else None
if _mitigator and _store:
    _mitigator.restore(_store.load_mitigations(500))

# Live feed for the web dashboard (/ui). Fed only by real pipeline activity.
_live = LiveFeed()
if _mitigator:
    _mitigator.on_record = lambda rec: _live.push("mitigation", rec.to_dict())


# ------------------------------------------------------------------
# Phase 3: Alert Manager
# ------------------------------------------------------------------
def _on_forwarded_alert(alert: Alert):
    """AlertManager callback → Mitigator."""
    if _mitigator:
        _mitigator.handle(alert)


_alert_manager: Optional[AlertManager] = None   # init after redis ready


# ------------------------------------------------------------------
# Phase 2: Threat Engine
# ------------------------------------------------------------------
def _on_threat(threat: ThreatEvent):
    """ThreatEngine callback → AlertManager."""
    with _lock:
        _recent_threats.append(threat)
        _counts_by_rule[threat.rule_id] += 1
    if _alert_manager:
        _alert_manager.receive(threat)
        hist = _alert_manager.get_history(limit=1)
        if hist:
            _live.push("alert", hist[-1].to_dict())


_engine = ThreatEngine(alert_callback=_on_threat)
if _store:
    _engine.persist = _store.save_state          # learned sessions/policies survive restarts

# NRF registry poller (thesis rule T08 + T01 baseline). Read-only GETs; set IDRS_NRF_POLL=off to disable.
_poller: Optional[RegistryPoller] = None


def _start_poller():
    global _poller
    if os.environ.get("IDRS_NRF_POLL", "on").lower() == "off":
        return
    _poller = RegistryPoller(on_snapshot=lambda snap: _engine.ingest_registry(snap),
                             interval=float(os.environ.get("IDRS_NRF_POLL_SEC", "10")))
    _poller.start()


# ------------------------------------------------------------------
# Phase 1: Redis consumer loop
# ------------------------------------------------------------------
def _consume_loop():
    global _alert_manager

    r = get_redis()
    _alert_manager = AlertManager(
        forward_callback = _on_forwarded_alert,
        redis_client     = r,
        store            = _store,
    )
    if _store:
        _alert_manager.restore(_store.load_alerts(1000))

    # resume (default): continue after the last processed event; beginning: replay all; latest: new only
    start = os.environ.get("NWDAF_START", "resume").lower()
    last_id = "$" if start == "latest" else ("0" if start == "beginning" else (r.get("nwdaf:last_id") or "0"))

    # Rebuild what the state-based rules (T02/T03/T09/T10) know, so sessions that predate this start are not
    # "unknown": from SQLite, or -- first run after an upgrade -- by replaying the capped stream, learn-only.
    rows = _store.load_state() if _store else []
    if rows:
        _engine.restore_state(rows)
        print(f"[NWDAF] restored {len(rows)} learned state entries from SQLite", flush=True)
    elif last_id not in ("0", "$"):
        n = 0
        try:
            for _mid, f in r.xrange(EVENTS_STREAM, "-", last_id):
                if f.get("data"):
                    _engine.learn_only(IDRSEvent.from_json(f["data"]))
                    n += 1
        except Exception as exc:
            print(f"[NWDAF] learn-only replay failed: {exc}", flush=True)
        print(f"[NWDAF] learned state from {n} historical events (no alerts raised)", flush=True)
    print(
        f"[NWDAF] pipeline ready — mitigation={_mitigator.mode if _mitigator else 'not installed'}",
        flush=True
    )

    while True:
        try:
            resp = r.xread({EVENTS_STREAM: last_id}, block=5000, count=100)
        except Exception as exc:
            print(f"[NWDAF] redis error: {exc}", flush=True)
            time.sleep(2)
            continue

        if not resp:
            continue

        for _stream, messages in resp:
            for msg_id, fields in messages:
                last_id = msg_id
                raw     = fields.get("data")
                if not raw:
                    continue
                try:
                    event = IDRSEvent.from_json(raw)
                except Exception:
                    continue

                with _lock:
                    _recent_events.append(event)
                    _counts_by_parser[event.parser]       += 1
                    _counts_by_interface[event.interface] += 1

                _live.observe_event(event)
                _engine.evaluate(event)
                if _poller and event.parser == "sbi_http2" and "nnrf-nfm" in (event.fields.get("path") or "") \
                        and event.fields.get("method") in ("PUT", "POST", "DELETE"):
                    _poller.poll_now()          # an NF (de)registered: refresh the registry baseline now
            try:
                r.set("nwdaf:last_id", last_id)
            except Exception:
                pass


def _stats_block() -> dict:
    with _lock:
        return {
            "total_events":  sum(_counts_by_parser.values()),
            "by_parser":     dict(_counts_by_parser),
            "by_interface":  dict(_counts_by_interface),
            "engine":        _engine.stats(),
            "alerts":        _alert_manager.stats() if _alert_manager else {},
            "mitigation":    _mitigator.stats() if _mitigator else {},
            "mitigation_mode": _mitigator.mode if _mitigator else "not installed",
        }


def _tick_loop():
    """1 Hz heartbeat: true per-interface rates + live counters for the dashboard."""
    while True:
        time.sleep(1.0)
        t = _live.drain_tick()
        t.update(_stats_block())
        t.update({"ts": time.time(), "boot_id": _live.boot_id,
                  "uptime": round(time.time() - _start_time, 1)})
        _live.push("tick", t)


def start_consumer():
    threading.Thread(target=_consume_loop, daemon=True).start()
    threading.Thread(target=_tick_loop, daemon=True).start()
    _start_poller()


# ==================================================================
# Web dashboard — /ui (page), /ui/snapshot (initial state), /stream (SSE)
# ==================================================================
UI_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ui", "index.html")


def _topology() -> dict:
    g = os.environ.get
    return {"core": g("IDRS_CORE_IP", "192.168.56.10"), "upf": g("IDRS_UPF_IP", "192.168.56.20"),
            "gnb":  g("IDRS_GNB_IP",  "192.168.56.30"), "ue":  g("IDRS_UE_IP",  "192.168.56.40")}


@app.get("/", include_in_schema=False)
def root():
    return RedirectResponse("/ui")


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def ui_page():
    with open(UI_FILE, encoding="utf-8") as f:     # read per request: edits show without restart
        return f.read()


@app.get("/ui/snapshot")
def ui_snapshot():
    with _lock:
        events = [compact_event(e) for e in list(_recent_events)[-100:]]
    alerts = [a.to_dict() for a in _alert_manager.get_history(limit=50)] if _alert_manager else []
    mit = [r.to_dict() for r in _mitigator.get_log(limit=50)] if _mitigator else []
    return {"boot_id": _live.boot_id, "seq": _live.seq, "topology": _topology(),
            "events": events, "alerts": alerts, "mitigation": mit,
            "stats": _stats_block(), "uptime": round(time.time() - _start_time, 1)}


@app.get("/stream")
async def stream(request: Request, since: Optional[int] = None):
    """Server-Sent Events. Reconnects resume from Last-Event-ID."""
    last = since if since is not None else int(request.headers.get("last-event-id") or _live.seq)
    if last > _live.seq:                      # server restarted; client will re-sync via boot_id
        last = 0

    async def gen():
        nonlocal last
        yield "retry: 2000\n\n"
        idle = 0
        while True:
            if await request.is_disconnected():
                break
            items = _live.after(last)
            for seq, kind, payload in items:
                last = seq
                yield f"id: {seq}\nevent: {kind}\ndata: {json.dumps(payload, default=str)}\n\n"
            idle = 0 if items else idle + 1
            if idle and idle % 75 == 0:
                yield ": keepalive\n\n"
            await asyncio.sleep(0.2)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ==================================================================
# Phase 1 — Base endpoints
# ==================================================================

@app.get("/health")
def health():
    return {
        "status":              "ok",
        "uptime_seconds":      round(time.time() - _start_time, 1),
        "mitigation_mode":     _mitigator.mode if _mitigator else "not installed",
        "version":             "0.5.0",
        "control_auth":        "X-API-Token required for state-changing endpoints",
        "persistence":         _store.path if _store else "disabled",
        "reads_protected":     PROTECT_READS,
        "rules_disabled":      sorted(_engine.disabled),
        "nrf_registry":        {"polling": bool(_poller), "instances": _poller.last_size if _poller else 0,
                                "last_ok": _poller.last_ok if _poller else None},
    }


@app.get("/stats")
def stats():
    with _lock:
        return {
            "total_events_seen":   sum(_counts_by_parser.values()),
            "by_parser":           dict(_counts_by_parser),
            "by_interface":        dict(_counts_by_interface),
            "buffer_size":         len(_recent_events),
            "threat_engine":       _engine.stats(),
            "alert_manager":       _alert_manager.stats() if _alert_manager else {},
            "mitigation":          _mitigator.stats() if _mitigator else {},
            "threats_by_rule":     dict(_counts_by_rule),
        }


@app.get("/events/recent")
def recent_events(
    limit:  int           = 50,
    parser: Optional[str] = None,
    supi:   Optional[str] = None,
):
    with _lock:
        items = list(_recent_events)
    if parser:
        items = [e for e in items if e.parser == parser]
    if supi:
        items = [e for e in items if e.supi   == supi]
    return [
        {
            "event_id": e.event_id, "timestamp":  e.timestamp,
            "parser":   e.parser,   "interface":  e.interface,
            "msg_type": e.msg_type, "src_ip":     e.src_ip,
            "dst_ip":   e.dst_ip,   "supi":       e.supi,
            "session_id": e.session_id, "fields": e.fields,
        }
        for e in items[-limit:]
    ]


@app.get("/nnwdaf-analyticsinfo/v1/summary")
def analytics_summary():
    with _lock:
        window = list(_recent_events)[-200:]
    if not window:
        return {"analytics": "no data yet"}
    span = window[-1].timestamp - window[0].timestamp if len(window) > 1 else 1
    return {
        "sample_size":              len(window),
        "approx_events_per_second": round(len(window) / span, 2),
        "distinct_supis_seen":      len({e.supi for e in window if e.supi}),
        "by_interface": {
            iface: sum(1 for e in window if e.interface == iface)
            for iface in {e.interface for e in window}
        },
    }


# ==================================================================
# Phase 2 — Threat Engine endpoints
# ==================================================================

@app.get("/threats/active")
def active_threats():
    threats = _engine.get_active()
    threats.sort(key=lambda t: t.score, reverse=True)
    return [t.to_dict() for t in threats]


@app.get("/threats/recent")
def recent_threats(
    limit:    int           = 50,
    rule_id:  Optional[str] = None,
    severity: Optional[str] = None,
    supi:     Optional[str] = None,
):
    with _lock:
        items = list(_recent_threats)
    if rule_id:
        items = [t for t in items if t.rule_id  == rule_id.upper()]
    if severity:
        items = [t for t in items if t.severity == severity.upper()]
    if supi:
        items = [t for t in items if t.supi     == supi]
    return [t.to_dict() for t in items[-limit:]]


@app.get("/threats/{threat_id}")
def get_threat(threat_id: str):
    for t in _engine.get_active():
        if t.threat_id == threat_id:
            return t.to_dict()
    raise HTTPException(404, "Threat not found")


@app.delete("/threats/{threat_id}", dependencies=[Depends(require_token)])
def clear_threat(threat_id: str):
    if not _engine.clear(threat_id):
        raise HTTPException(404, "Threat not found")
    return {"status": "cleared", "threat_id": threat_id}


@app.get("/threats/summary/by-rule")
def by_rule():
    with _lock:
        return dict(_counts_by_rule)


@app.get("/nnwdaf-analyticsinfo/v1/threats")
def nwdaf_threat_analytics():
    threats  = _engine.get_active()
    critical = [t for t in threats if t.severity.value == "CRITICAL"]
    warning  = [t for t in threats if t.severity.value == "WARNING"]
    return {
        "analyticsId":     "ABNORMAL_BEHAVIOUR",
        "nwdafInstanceId": "idrs-nwdaf-001",
        "generatedAt":      time.time(),
        "summary": {
            "total_active": len(threats),
            "critical":     len(critical),
            "warning":      len(warning),
        },
        "topThreats": [
            {
                "ruleId":     t.rule_id,   "ruleName":   t.rule_name,
                "score":      t.score,     "severity":   t.severity.value,
                "supi":       t.supi,      "interface":  t.interface,
                "detectedAt": t.detected_at,
            }
            for t in sorted(threats, key=lambda x: x.score, reverse=True)[:10]
        ],
    }


# ==================================================================
# Phase 3 — Alert Manager endpoints
# ==================================================================

@app.get("/alerts/history")
def alert_history(
    limit:     int            = 100,
    rule_id:   Optional[str]  = None,
    severity:  Optional[str]  = None,
    forwarded: Optional[bool] = None,
):
    if not _alert_manager:
        return []
    return [
        a.to_dict()
        for a in _alert_manager.get_history(
            limit=limit, rule_id=rule_id,
            severity=severity, forwarded=forwarded
        )
    ]


@app.get("/alerts/actionable")
def actionable_alerts():
    """CRITICAL alerts forwarded to the Mitigation Module."""
    if not _alert_manager:
        return []
    alerts = _alert_manager.get_history(limit=200, forwarded=True)
    alerts.sort(key=lambda a: a.threat.score, reverse=True)
    return [a.to_dict() for a in alerts]


@app.get("/alerts/stats")
def alert_stats():
    return _alert_manager.stats() if _alert_manager else {}


@app.get("/alerts")
def list_alerts(page: int = 1, page_size: int = 50, tier: Optional[str] = None, rule_id: Optional[str] = None,
                supi: Optional[str] = None, forwarded: Optional[bool] = None):
    """Thesis 3.4.5: paginated alert list (newest first) with tier / rule / SUPI filters."""
    if not _alert_manager:
        return {"page": page, "page_size": page_size, "total": 0, "items": []}
    items = _alert_manager.get_history(limit=100000, rule_id=rule_id, severity=tier, forwarded=forwarded)
    if supi:
        items = [a for a in items if a.threat.supi == supi]
    items.reverse()
    page_size = max(1, min(page_size, 500)); page = max(1, page)
    return {"page": page, "page_size": page_size, "total": len(items),
            "items": [a.to_dict() for a in items[(page - 1) * page_size: page * page_size]]}


@app.get("/alerts/{threat_id}")
def get_alert(threat_id: str):
    """Thesis 3.4.5: one alert with its full evidence."""
    if _alert_manager:
        for a in _alert_manager.get_history(limit=100000):
            if a.threat.threat_id == threat_id:
                return a.to_dict()
    raise HTTPException(404, "Alert not found")


@app.post("/rules/{rule_id}/threshold", dependencies=[Depends(require_token)])
async def set_rule_threshold(rule_id: str, request: Request):
    """Thesis 3.4.5: runtime threshold update without restart. Body: {"threshold": <number>}."""
    try:
        body = await request.json()
        return {"rule_id": rule_id.upper(), "thresholds": _engine.set_rule_threshold(rule_id, body["threshold"])}
    except (KeyError, TypeError):
        raise HTTPException(400, 'body must be {"threshold": <number>}')
    except ValueError as exc:
        raise HTTPException(400, str(exc))


# ==================================================================
# Phase 4 — Mitigation endpoints (present only when mitigator.py is installed)
# ==================================================================

if _mitigator:
    @app.get("/mitigation/log")
    def mitigation_log(limit: int = 100, success: Optional[bool] = None,
                       action: Optional[str] = None):
        return [r.to_dict() for r in _mitigator.get_log(limit=limit, success=success, action=action)]

    @app.get("/mitigation/stats")
    def mitigation_stats():
        return _mitigator.stats()

    @app.get("/mitigation/failed")
    def mitigation_failed(limit: int = 50):
        return [r.to_dict() for r in _mitigator.get_log(limit=limit, success=False)]

    @app.post("/mitigation/mode/{mode}", dependencies=[Depends(require_token)])
    def set_mitigation_mode(mode: str):
        """off | dry_run | enforce -- switch without restarting."""
        if mode not in ("off", "dry_run", "enforce"):
            raise HTTPException(400, "mode must be off, dry_run or enforce")
        _mitigator.mode = mode
        return {"mitigation_mode": mode}

    @app.post("/mitigations/{mitigation_id}/rollback", dependencies=[Depends(require_token)])
    @app.post("/mitigation/{mitigation_id}/rollback", dependencies=[Depends(require_token)])
    def rollback_mitigation(mitigation_id: str):
        """Undo an executed NRF action (re-register deleted NF / un-suspend)."""
        try:
            rec = _mitigator.rollback(mitigation_id)
        except KeyError:
            raise HTTPException(404, "unknown mitigation id")
        except ValueError as exc:
            raise HTTPException(409, str(exc))
        return rec.to_dict()


# ==================================================================
# Runtime thresholds (read: open; change: token)
# ==================================================================
@app.get("/config/rules")
def get_rules():
    return _engine.rules_state()


@app.put("/config/rules", dependencies=[Depends(require_token)])
async def put_rules(request: Request):
    """Enable/disable rules at runtime, e.g. {"T09": true}. T09 is off until the GTP-U sensor feeds it."""
    try:
        for rule, on in (await request.json()).items():
            _engine.set_rule_enabled(rule, bool(on))
        return _engine.rules_state()
    except (ValueError, AttributeError) as exc:
        raise HTTPException(400, str(exc))


@app.get("/config/baseline")
def get_baseline():
    """Observed per-interface PPS (baseline, peak) and the T06 floor/threshold in force.
    Run normal traffic (attach your UEs), then set T06 floors to ~1.5x the peak via PUT /config/thresholds."""
    return _engine.pps_stats()


@app.get("/config/thresholds")
def get_thresholds():
    return _engine.get_thresholds()


@app.put("/config/thresholds", dependencies=[Depends(require_token)])
async def put_thresholds(request: Request):
    try:
        return _engine.set_thresholds(await request.json())
    except (ValueError, TypeError) as exc:
        raise HTTPException(400, str(exc))


def announce_token():
    print(f"[NWDAF] control token ({'generated' if TOKEN_GENERATED else 'from IDRS_API_TOKEN'}): {API_TOKEN}"
          if TOKEN_GENERATED else "[NWDAF] control token loaded from IDRS_API_TOKEN", flush=True)


if __name__ == "__main__":
    uvicorn.run(
        app,
        host = "0.0.0.0",
        port = int(os.environ.get("NWDAF_PORT", "8090")),
    )
