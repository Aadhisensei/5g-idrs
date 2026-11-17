"""
nwdaf/mitigator.py -- Attack Mitigation Module.

MODES (env MITIGATION_MODE, default dry_run; MITIGATION_ENABLED=false -> off,
MITIGATION_DRY_RUN=false -> enforce are accepted as aliases):
  off      do nothing
  dry_run  record the SBI request that WOULD be sent; nothing leaves the host
  enforce  send the request

* Actions run on a background worker (bounded queue), so a slow/unresponsive SBI peer can
  never stall detection in the NWDAF consumer thread.
* Open5GS SBI is HTTP/2 cleartext with prior knowledge -> httpx(http1=False, http2=True).
* An action runs only when the identifiers it needs are known; otherwise it is recorded as
  SKIPPED with the reason (never a guessed/invalid request).
* Executed NRF actions store an undo request; POST /mitigation/{id}/rollback replays it.

  reject_nf_registration  non-loopback source IP  -> locate NF profile, DELETE   (undo: PUT saved profile)
  block_sbi_caller        non-loopback source IP  -> JSON-Patch nfStatus=SUSPENDED (undo: back to REGISTERED)
  terminate_session       evidence.sm_context_ref -> SMF sm-contexts/{ref}/release (not reversible)
  notify_operator         log only
NRF/SMF request shapes follow TS 29.510 / 29.502 and were tested against a stub only.
"""
import json
import os
import queue
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Deque, List, Optional

from nwdaf.alert_manager import Alert

NRF_BASE = os.environ.get("IDRS_NRF_URL", "http://127.0.0.10:7777")
SMF_BASE = os.environ.get("IDRS_SMF_URL", "http://127.0.0.4:7777")
MODES = ("off", "dry_run", "enforce")
NF_TYPES = ("AMF", "SMF", "UPF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "BSF", "NWDAF", "SCP")
JSON_PATCH = "application/json-patch+json"


@dataclass
class MitigationRecord:
    mitigation_id: str
    rule_id: str
    action: str
    target: str
    status: str                  # executed | failed | dry_run | skipped | notified | dropped
    detail: str
    sbi_endpoint: Optional[str] = None
    http_status: Optional[int] = None
    executed_at: float = field(default_factory=time.time)
    undo: Optional[dict] = None          # request that reverses this action
    rolled_back: bool = False

    @property
    def success(self) -> bool:
        return self.status in ("executed", "dry_run", "notified")

    def to_dict(self, public: bool = True) -> dict:
        d = asdict(self)
        d["success"] = self.success
        d["can_rollback"] = bool(self.undo) and not self.rolled_back
        if public:
            d.pop("undo", None)          # may hold a full NF profile; never sent to the browser
        return d

    @staticmethod
    def from_dict(d: dict) -> "MitigationRecord":
        keys = MitigationRecord.__dataclass_fields__.keys()
        return MitigationRecord(**{k: v for k, v in d.items() if k in keys})


def initial_mode_from_env() -> str:
    m = os.environ.get("MITIGATION_MODE", "").lower()
    if m in MODES:
        return m
    if os.environ.get("MITIGATION_ENABLED", "").lower() in ("false", "0", "no"):
        return "off"
    if os.environ.get("MITIGATION_DRY_RUN", "").lower() in ("false", "0", "no"):
        return "enforce"
    return "dry_run"


class Mitigator:
    MAX_LOG, QUEUE_MAX = 500, 200

    def __init__(self, mode: str = "dry_run", store=None):
        self.mode = mode if mode in MODES else "dry_run"
        self._store = store
        self._log: Deque[MitigationRecord] = deque(maxlen=self.MAX_LOG)
        self._lock = threading.Lock()
        self._client = None
        self.on_record = None                       # callback(record) -> live dashboard
        self._q: "queue.Queue[Alert]" = queue.Queue(maxsize=self.QUEUE_MAX)
        self._worker = None
        self._wlock = threading.Lock()

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    def restore(self, rows: List[dict]):
        with self._lock:
            for d in rows:
                try:
                    self._log.append(MitigationRecord.from_dict(d))
                except Exception:
                    continue

    # ------------------------------------------------------------ public
    def handle(self, alert: Alert):
        """Non-blocking: queue the alert for the worker thread."""
        if self.mode == "off" or not alert.mitigation:
            return
        with self._wlock:
            if self._worker is None:
                self._worker = threading.Thread(target=self._run, name="mitigator", daemon=True)
                self._worker.start()
        try:
            self._q.put_nowait(alert)
        except queue.Full:
            self._emit([self._rec(alert, alert.mitigation, "n/a", "dropped",
                                  "mitigation queue full; alert kept in history")])

    def flush(self, timeout: float = 10.0) -> bool:
        """Wait until queued alerts are processed (used by tests/shutdown)."""
        end = time.time() + timeout
        while time.time() < end:
            if self._q.unfinished_tasks == 0:
                return True
            time.sleep(0.02)
        return False

    def get_log(self, limit=100, success: Optional[bool] = None, action: Optional[str] = None):
        with self._lock:
            items = list(self._log)
        if success is not None:
            items = [r for r in items if r.success == success]
        if action:
            items = [r for r in items if r.action.startswith(action)]
        return items[-limit:]

    def stats(self) -> dict:
        with self._lock:
            items = list(self._log)
        out = {"mode": self.mode, "total": len(items), "queued": self._q.qsize()}
        for st in ("executed", "failed", "dry_run", "skipped", "notified", "dropped"):
            out[st] = sum(1 for r in items if r.status == st)
        out["rolled_back"] = sum(1 for r in items if r.rolled_back)
        return out

    def rollback(self, mitigation_id: str) -> MitigationRecord:
        with self._lock:
            rec = next((r for r in self._log if r.mitigation_id == mitigation_id), None)
        if rec is None:
            raise KeyError("unknown mitigation id")
        if not rec.undo:
            raise ValueError("this action is not reversible")
        if rec.rolled_back:
            raise ValueError("already rolled back")
        u = rec.undo
        res = self._send(None, f"rollback:{rec.action}", rec.target, u["method"], u["url"],
                         u.get("body"), u.get("ctype", "application/json"), rule_id=rec.rule_id)
        if res.status == "executed":
            rec.rolled_back = True
            if self._store:
                self._store.save_mitigation(rec.to_dict(public=False))
        self._emit([res])
        return res

    # ------------------------------------------------------------ worker
    def _run(self):
        while True:
            alert = self._q.get()
            try:
                self._process(alert)
            except Exception as exc:
                self._emit([self._rec(alert, alert.mitigation, "n/a", "failed", f"exception: {exc}")])
            finally:
                self._q.task_done()

    def _process(self, alert: Alert):
        if self.mode == "off":
            return
        fn = {"reject_nf_registration": self._reject_nf, "block_sbi_caller": self._suspend_nf,
              "terminate_session": self._terminate_session, "notify_operator": self._notify,
              }.get(alert.mitigation)
        if fn:
            self._emit(fn(alert))

    def _emit(self, recs: List[MitigationRecord]):
        with self._lock:
            self._log.extend(recs)
        for r in recs:
            if self._store:
                try:
                    self._store.save_mitigation(r.to_dict(public=False))
                except Exception:
                    pass
            if self.on_record:
                try:
                    self.on_record(r)
                except Exception:
                    pass
            print(f"[Mitigator:{self.mode}] {r.rule_id} {r.action} -> {r.status} ({r.detail})", flush=True)

    # ----------------------------------------------------------- actions
    def _notify(self, a: Alert):
        return [self._rec(a, "notify_operator", a.threat.src_ip or "n/a", "notified",
                          f"{a.threat.rule_name} score={a.threat.score}")]

    @staticmethod
    def _untrusted_ip(a: Alert) -> Optional[str]:
        ip = a.threat.src_ip
        return ip if ip and not ip.startswith("127.") else None

    def _reject_nf(self, a: Alert):
        ids = list(a.threat.evidence.get("nf_instance_ids") or [])
        ip = self._untrusted_ip(a)
        if not ids and not ip:
            return [self._rec(a, "reject_nf_registration", "n/a", "skipped",
                              "no nfInstanceId (needs an NRF registry baseline) and the source is loopback/unknown")]
        if self.mode == "dry_run":
            what = f"nfInstanceIds {ids}" if ids else f"the NRF profile with ipv4Address={ip}"
            return [self._rec(a, "reject_nf_registration", ",".join(ids) or ip, "dry_run",
                              f"would DELETE {what} at the NRF", NRF_BASE)]
        recs, targets = [], []
        if ids:
            for nf_id in ids[:50]:
                pr = self._http().get(f"{NRF_BASE}/nnrf-nfm/v1/nf-instances/{nf_id}")
                if pr.status_code != 200:                      # expired/re-registered meanwhile: leave it alone
                    recs.append(self._rec(a, "reject_nf_registration", nf_id, "skipped",
                                          f"NF instance no longer in the NRF (GET {pr.status_code})"))
                    continue
                targets.append((nf_id, pr.json()))
        else:
            targets = self._find_nf_by_ip(ip)
        for nf_id, profile in targets:
            url = f"{NRF_BASE}/nnrf-nfm/v1/nf-instances/{nf_id}"
            r = self._send(a, "reject_nf_registration", nf_id, "DELETE", url)
            if r.status == "executed" and profile:
                r.undo = {"method": "PUT", "url": url, "body": profile, "ctype": "application/json"}
            recs.append(r)
        return recs or [self._rec(a, "reject_nf_registration", ip or "n/a", "skipped", "no matching NF profile")]

    def _suspend_nf(self, a: Alert):
        ip = self._untrusted_ip(a)
        if not ip:
            return [self._rec(a, "block_sbi_caller", "n/a", "skipped",
                              "caller is loopback/unknown: suspending by NF type would risk legitimate NFs")]
        if self.mode == "dry_run":
            return [self._rec(a, "block_sbi_caller", ip, "dry_run",
                              f"would JSON-Patch the NRF profile with ipv4Address={ip}: nfStatus=SUSPENDED", NRF_BASE)]
        recs = []
        for nf_id, _profile in self._find_nf_by_ip(ip):
            url = f"{NRF_BASE}/nnrf-nfm/v1/nf-instances/{nf_id}"
            body = [{"op": "replace", "path": "/nfStatus", "value": "SUSPENDED"}]
            r = self._send(a, "block_sbi_caller", ip, "PATCH", url, body, JSON_PATCH)
            if r.status == "executed":
                r.undo = {"method": "PATCH", "url": url, "ctype": JSON_PATCH,
                          "body": [{"op": "replace", "path": "/nfStatus", "value": "REGISTERED"}]}
            recs.append(r)
        return recs or [self._rec(a, "block_sbi_caller", ip, "skipped", "no NF profile matches this IP")]

    def _terminate_session(self, a: Alert):
        ref = a.threat.evidence.get("sm_context_ref")
        if not ref:
            return [self._rec(a, "terminate_session", str(a.threat.evidence.get("seid")), "skipped",
                              "SEID cannot be mapped to an SMF smContextRef yet")]
        url = f"{SMF_BASE}/nsmf-pdusession/v1/sm-contexts/{ref}/release"
        if self.mode == "dry_run":
            return [self._rec(a, "terminate_session", str(ref), "dry_run", f"would POST {url}", url)]
        return [self._send(a, "terminate_session", str(ref), "POST", url, {})]

    # ------------------------------------------------------------ SBI I/O
    def _http(self):
        if self._client is None:
            import httpx
            self._client = httpx.Client(http1=False, http2=True, timeout=5.0)   # h2c prior knowledge
        return self._client

    def _find_nf_by_ip(self, ip: str):
        """[(nf_instance_id, profile)] whose address matches ip. Tries the NF list first,
        then per-type discovery (target-nf-type is mandatory; requester is us, an NWDAF)."""
        c = self._http()

        def has_ip(prof):
            addrs = list(prof.get("ipv4Addresses", []))
            for svc in prof.get("nfServices", []) or []:
                addrs += [e.get("ipv4Address") for e in svc.get("ipEndPoints", []) or []]
            return ip in addrs

        found = []
        resp = c.get(f"{NRF_BASE}/nnrf-nfm/v1/nf-instances")
        if resp.status_code == 200:
            data = resp.json()
            hrefs = [i.get("href", "") for i in data.get("_links", {}).get("item", [])]
            hrefs += [f"/{i.get('nfInstanceId')}" for i in data.get("nfInstances", []) if i.get("nfInstanceId")]
            for href in hrefs:
                nf_id = href.rstrip("/").split("/")[-1]
                pr = c.get(f"{NRF_BASE}/nnrf-nfm/v1/nf-instances/{nf_id}")
                if pr.status_code == 200 and has_ip(pr.json()):
                    found.append((nf_id, pr.json()))
            return found
        for t in NF_TYPES:                                  # fallback: discovery
            r = c.get(f"{NRF_BASE}/nnrf-disc/v1/nf-instances",
                      params={"target-nf-type": t, "requester-nf-type": "NWDAF"})
            if r.status_code == 200:
                for prof in r.json().get("nfInstances", []):
                    if has_ip(prof) and prof.get("nfInstanceId"):
                        found.append((prof["nfInstanceId"], prof))
        return found

    def _send(self, a, action, target, method, url, body=None, ctype="application/json", rule_id=None):
        try:
            kw = {"headers": {"Content-Type": ctype, "Accept": "application/json"}}
            if body is not None:
                kw["content"] = json.dumps(body)
            r = self._http().request(method, url, **kw)
            ok = r.status_code in (200, 201, 204)
            return self._rec(a, action, target, "executed" if ok else "failed",
                             f"{method} {r.status_code} {r.text[:120]}", url, r.status_code, rule_id)
        except Exception as exc:
            return self._rec(a, action, target, "failed", f"{method} error: {exc}", url, None, rule_id)

    @staticmethod
    def _rec(a, action, target, status, detail, endpoint=None, http_status=None, rule_id=None):
        return MitigationRecord(str(uuid.uuid4()), rule_id or (a.threat.rule_id if a else "unknown"), action, target,
                                status, detail, endpoint, http_status)
