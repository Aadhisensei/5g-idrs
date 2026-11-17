"""
nwdaf/nrf_registry.py -- polls the NRF registry (read-only GETs over HTTP/2 cleartext) so the engine can
detect rogue NFs by NF-type conflict (thesis rule T08) and so T01 knows which NF instances are established.
Lookup order: NF list (TS 29.510 NFListRetrieval), then per-type discovery (requester = NWDAF).
If the NRF refuses both, the poller logs it once and T08 stays silent.
"""
import os
import threading
import time
from typing import Callable, Dict, Optional

NRF_BASE = os.environ.get("IDRS_NRF_URL", "http://127.0.0.10:7777")
NF_TYPES = ("AMF", "SMF", "UPF", "AUSF", "UDM", "UDR", "PCF", "NSSF", "BSF", "NWDAF", "SCP")


def fetch_registry(base: str = None, client=None) -> Optional[Dict[str, dict]]:
    import httpx
    base = base or NRF_BASE
    c = client or httpx.Client(http1=False, http2=True, timeout=4.0)
    out: Dict[str, dict] = {}
    resp = c.get(f"{base}/nnrf-nfm/v1/nf-instances")
    if resp.status_code == 200:
        data = resp.json()
        hrefs = [i.get("href", "") for i in data.get("_links", {}).get("item", [])]
        hrefs += [f"/{i.get('nfInstanceId')}" for i in data.get("nfInstances", []) if i.get("nfInstanceId")]
        for href in hrefs:
            nid = href.rstrip("/").split("/")[-1]
            pr = c.get(f"{base}/nnrf-nfm/v1/nf-instances/{nid}")
            if pr.status_code == 200:
                out[nid] = pr.json()
        return out
    got = False
    for t in NF_TYPES:
        r = c.get(f"{base}/nnrf-disc/v1/nf-instances", params={"target-nf-type": t, "requester-nf-type": "NWDAF"})
        if r.status_code == 200:
            got = True
            for prof in r.json().get("nfInstances", []):
                if prof.get("nfInstanceId"):
                    out[prof["nfInstanceId"]] = prof
    return out if got else None


class RegistryPoller(threading.Thread):
    def __init__(self, on_snapshot: Callable[[Dict[str, dict]], None], interval: float = 10.0, base: str = None):
        super().__init__(name="nrf-registry", daemon=True)
        self.on_snapshot, self.interval, self.base = on_snapshot, interval, base
        self._wake, self._last, self._warned = threading.Event(), 0.0, False
        self.last_ok: Optional[float] = None
        self.last_size = 0

    def poll_now(self):
        """Ask for an immediate poll (rate-limited to 1/s); used when an NRF registration is observed."""
        if time.time() - self._last > 1.0:
            self._wake.set()

    def run(self):
        while True:
            self._wake.wait(self.interval)
            self._wake.clear()
            self._last = time.time()
            try:
                snap = fetch_registry(self.base)
                if snap is None:
                    if not self._warned:
                        print("[NRF registry] list/discovery refused by the NRF; T08 disabled", flush=True)
                        self._warned = True
                    continue
                self.last_ok, self.last_size, self._warned = time.time(), len(snap), False
                self.on_snapshot(snap)
            except Exception as exc:
                if not self._warned:
                    print(f"[NRF registry] poll failed: {exc}", flush=True)
                    self._warned = True
