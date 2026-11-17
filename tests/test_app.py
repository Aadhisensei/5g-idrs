"""App-level tests: auth (writes + reads), thesis REST API, persistence, resume, stream caps, mitigator.
Run: PYTHONPATH=. python3 tests/test_app.py   (needs hypercorn + fakeredis)"""
import os, subprocess, sys, tempfile, time, fakeredis

TMP = tempfile.mkdtemp(); os.environ.update({"IDRS_DB": f"{TMP}/idrs.db", "IDRS_API_TOKEN": "s3cret",
                                             "MITIGATION_MODE": "dry_run", "IDRS_NRF_POLL": "off"})
import common.redis_client as rc
fake = fakeredis.FakeRedis(decode_responses=True); rc.get_redis = lambda: fake
import nwdaf.app as A
A.get_redis = lambda: fake
import nwdaf.mitigator as M
from common.events import IDRSEvent
from fastapi.testclient import TestClient
from nwdaf.alert_manager import Alert, AlertManager
from nwdaf.store import Store
from nwdaf.threat_models import ThreatEvent, ThreatCategory, Severity

res = []
def check(name, cond, extra=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}"); res.append(bool(cond))
H = {"X-API-Token": "s3cret"}
now = time.time()
def nas_reg(gnb, ts):
    return IDRSEvent(parser="nas", interface="N1", msg_type="Registration Request", src_ip=gnb, dst_ip="192.168.56.10",
                     supi="imsi-999700000000001", fields={"ran_ue_ngap_id": 7}, timestamp=ts)
rc.publish_event(fake, nas_reg("192.168.56.30", now)); rc.publish_event(fake, nas_reg("192.168.56.31", now + 1))   # T04
rc.publish_event(fake, IDRSEvent(parser="pfcp", interface="N4", msg_type="Session Establishment Response", src_ip="192.168.56.20", dst_ip="192.168.56.10",
                                 session_id="1", fields={"fseid": "3599", "ul_teids": [43981]}, timestamp=now + 2))
with TestClient(A.app) as c:
    time.sleep(1.5)
    # ---- auth: writes AND reads
    check("health/ui shell stay open", c.get("/health").status_code == 200 and c.get("/ui").status_code == 200)
    for path in ("/stats", "/ui/snapshot", "/alerts", "/threats/active", "/events/recent", "/config/thresholds", "/mitigation/log"):
        check(f"read {path} without token -> 401", c.get(path).status_code == 401)
    check("read with header token", c.get("/stats", headers=H).status_code == 200)
    check("read with ?token= (EventSource style)", c.get("/stats?token=s3cret").status_code == 200)
    check("wrong token -> 401", c.get("/stats", headers={"X-API-Token": "no"}).status_code == 401)
    check("DELETE /threats without token -> 401", c.delete("/threats/x").status_code == 401)
    check("DELETE /threats with token -> 404 (authorised, unknown id)", c.delete("/threats/x", headers=H).status_code == 404)
    check("mode switch needs token", c.post("/mitigation/mode/off").status_code == 401 and c.post("/mitigation/mode/dry_run", headers=H).status_code == 200)
    # ---- thesis REST API
    a = c.get("/alerts", headers=H).json()
    check("GET /alerts paginated envelope", set(a) >= {"page", "page_size", "total", "items"} and a["total"] >= 1)
    t04 = [x for x in a["items"] if x["rule_id"] == "T04"]
    check("T04 (same IMSI via two gNBs) detected end-to-end, tier CRITICAL, score 0-100", bool(t04) and t04[0]["tier"] == "CRITICAL" and 70 <= t04[0]["score"] <= 100, f"({t04[0]['score'] if t04 else None})")
    check("alert filter by tier/rule", c.get("/alerts?tier=CRITICAL&rule_id=T04", headers=H).json()["total"] >= 1 and c.get("/alerts?tier=INFO", headers=H).json()["total"] == 0)
    tid = t04[0]["threat_id"] if t04 else "x"
    check("GET /alerts/{id} returns full evidence", c.get(f"/alerts/{tid}", headers=H).json().get("evidence", {}).get("gnbs") is not None and c.get("/alerts/none", headers=H).status_code == 404)
    check("POST /rules/{id}/threshold needs token", c.post("/rules/X01/threshold", json={"threshold": 9}).status_code == 401)
    check("POST /rules/{id}/threshold applies at runtime", c.post("/rules/X01/threshold", json={"threshold": 9}, headers=H).json()["thresholds"]["X01_THRESH"] == 9)
    check("bad threshold requests rejected", c.post("/rules/T03/threshold", json={"threshold": 1}, headers=H).status_code == 400 and c.post("/rules/X01/threshold", json={"nope": 1}, headers=H).status_code == 400)
    check("PUT /config/thresholds", c.put("/config/thresholds", json={"T01_THRESH": 25}, headers=H).json()["T01_THRESH"] == 25 and c.put("/config/thresholds", json={"NOPE": 1}, headers=H).status_code == 400)
    # ---- mitigation record, persistence, resume
    time.sleep(0.5)
    mlog = c.get("/mitigation/log", headers=H).json()
    check("CRITICAL alert reached the mitigator (T04 -> terminate_session, skipped: no smContextRef)", any(r["rule_id"] == "T04" and r["status"] == "skipped" for r in mlog))
    check("alert + mitigation persisted to SQLite", any(x["rule_id"] == "T04" for x in Store(os.environ["IDRS_DB"]).load_alerts()) and any(x["rule_id"] == "T04" for x in Store(os.environ["IDRS_DB"]).load_mitigations()))
    check("last processed id saved for resume", bool(fake.get("nwdaf:last_id")))
    check("rollback routes need token; unknown id -> 404", c.post("/mitigations/abc/rollback").status_code == 401 and c.post("/mitigations/abc/rollback", headers=H).status_code == 404)
    check("mitigation log hides undo payload", all("undo" not in r for r in mlog))
    check("/config/rules: T09 off by default, toggled with token", c.get("/config/rules", headers=H).json()["T09"] is False and c.put("/config/rules", json={"T09": True}).status_code == 401 and c.put("/config/rules", json={"T09": True}, headers=H).json()["T09"] is True and c.put("/config/rules", json={"NOPE": True}, headers=H).status_code == 400)
    check("/config/baseline reports per-interface rates", isinstance(c.get("/config/baseline", headers=H).json(), dict))
    check("/health shows disabled rules", "T09" not in c.get("/health").json()["rules_disabled"])
    s = c.get("/ui/snapshot", headers=H).json()
    check("snapshot ok with token", s["stats"]["mitigation_mode"] == "dry_run" and "topology" in s)

st = Store(os.environ["IDRS_DB"]).load_state()
check("engine learned state (SEID, TEID, first_ts) persisted to SQLite", {"seid", "ul_teid", "meta"} <= {k for k, _, _ in st}, f"({len(st)} rows)")
from nwdaf.threat_engine import ThreatEngine
eng = ThreatEngine(); eng.restore_state(st)
check("a fresh engine restored from SQLite already knows the session", "3599" in eng._seids and 43981 in eng._ul_teids)
am = AlertManager(store=None); am.restore(Store(os.environ["IDRS_DB"]).load_alerts())
check("alert history restored after restart", any(x.threat.rule_id == "T04" for x in am.get_history()))
rc.STREAM_MAXLEN = 100
for i in range(2000): rc.xadd_capped(fake, "t:cap", {"d": str(i)})
check("Redis stream is capped", fake.xlen("t:cap") < 400, f"(xlen={fake.xlen('t:cap')})")

# ---- mitigator vs HTTP/2-cleartext NRF/SMF stubs
def stub(port, env=None):
    p = subprocess.Popen([sys.executable, "-m", "hypercorn", "stub_sbi:app", "--bind", f"127.0.0.1:{port}"], cwd="tests",
                         env={**os.environ, **(env or {})}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); time.sleep(2); return p
def mk(rule, action, ip=None, **ev):
    t = ThreatEvent(rule_id=rule, rule_name="x", category=ThreatCategory.ROGUE_NF, score=90.0, severity=Severity.CRITICAL, supi=None,
                    src_ip=ip, interface="SBI", parser="sbi_http2", trigger_msg="x", evidence=ev)
    return Alert(t, True, False, action)
import httpx
procs = [stub(7792), stub(7793, {"STUB_NO_LIST": "1"})]
try:
    state = lambda port: httpx.Client(http1=False, http2=True).get(f"http://127.0.0.1:{port}/__state").json()
    M.NRF_BASE = "http://127.0.0.1:7792"; M.SMF_BASE = M.NRF_BASE
    m = M.Mitigator(mode="enforce")
    m.handle(mk("T08", "reject_nf_registration", None, nf_instance_ids=["bad"])); m.flush()
    r = m.get_log()[-1]
    check("T08: rogue NF deleted by nfInstanceId, legit AMF untouched", r.status == "executed" and "bad" not in state(7792) and "aaa" in state(7792), f"({r.status})")
    check("undo stored, hidden from public dict", r.undo is not None and "undo" not in r.to_dict() and r.to_dict()["can_rollback"])
    check("rollback re-registers the NF", m.rollback(r.mitigation_id).status == "executed" and "bad" in state(7792))
    try: m.rollback(r.mitigation_id); check("second rollback refused", False)
    except ValueError: check("second rollback refused", True)
    m.handle(mk("T01", "reject_nf_registration", "127.0.0.1", nf_instance_ids=[])); m.flush()
    check("no ids + loopback source -> skipped, nothing sent", m.get_log()[-1].status == "skipped" and "bad" in state(7792))
    for port, label in ((7792, "list"), (7793, "discovery-fallback")):
        M.NRF_BASE = f"http://127.0.0.1:{port}"
        m = M.Mitigator(mode="enforce")
        m.handle(mk("T08", "reject_nf_registration", "192.168.56.99")); m.flush()   # legacy path: lookup by address
        check(f"[{label}] lookup by address removes only the matching NF", m.get_log()[-1].status == "executed" and "bad" not in state(port) and "aaa" in state(port))
        m.rollback(m.get_log()[-1].mitigation_id)
    M.NRF_BASE = "http://127.0.0.1:7792"; m = M.Mitigator(mode="enforce")
    m.handle(mk("T04", "block_sbi_caller", "192.168.56.99")); m.flush()
    check("suspend via JSON-Patch + un-suspend rollback", state(7792)["bad"]["nfStatus"] == "SUSPENDED" and m.rollback(m.get_log()[-1].mitigation_id).status == "executed" and state(7792)["bad"]["nfStatus"] == "REGISTERED")
    M.SMF_BASE = M.NRF_BASE
    t0 = time.time(); m.handle(mk("T02", "terminate_session", None, sm_context_ref="9")); dt = time.time() - t0
    check("slow SMF does not block the caller", dt < 0.3, f"(handle() returned in {dt*1000:.0f} ms)")
    m.flush(); check("slow SMF call completes in background", m.get_log()[-1].status == "executed")
    import nwdaf.nrf_registry as R
    snap = R.fetch_registry("http://127.0.0.1:7792"); snap2 = R.fetch_registry("http://127.0.0.1:7793")
    check("registry poller: list and discovery-fallback both return the NF registry", set(snap) == {"aaa", "bad"} and set(snap2) == {"aaa", "bad"})
finally:
    for p in procs: p.terminate()
print("\nALL PASS" if all(res) else "\nSOME FAILED"); sys.exit(0 if all(res) else 1)
