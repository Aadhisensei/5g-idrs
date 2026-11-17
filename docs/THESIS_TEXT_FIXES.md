# Ready-to-paste thesis corrections (match the build as of 30 Oct 2026)

Facts below are taken from the code and the thesis PDF. Evaluation numbers (detection latency, false-positive rate,
load) are NOT included: they must come from the Phase 5 experiments.

## §3.2.1 (versions)  -> "UERANSIM v3.2.8" (the screenshots in Figs 4.1/4.2 print v3.2.8).
## §3.3 step 2         -> "...coordinates 5G-AKA authentication with the AUSF (N12), which obtains credentials from the UDM (N13)..."
## §3.2.3 (NAS security)  Replace "NAS security algorithms NIA2 and NEA2" by the configuration actually in `amf.yaml`.
The UE log (Fig 4.2) shows `integrity[2] ciphering[0]` = NIA2 with NEA0. State that and add:
"With NEA0 all NAS messages are readable by the IDRS NAS parser; with NEA2 only messages sent before NAS security is
activated (Registration Request, Identity, Authentication) remain readable."

## §3.4.1 / Abstract / §1.1 / §4.1 / §5.2 (status)
Replace "have not been implemented" by: "The parsers, threat evaluation engine, alert manager, mitigation module and a
live monitoring dashboard were implemented as a Python microservice coupled to a custom NWDAF; functional validation
on the testbed and attack-based evaluation are reported in Chapter 4 [to be completed]."

## §3.4.3 (parsers)
"SBI/HTTP2 traffic is decoded with tshark (via pyshark), because HPACK header compression requires the start of each
connection; NGAP is decoded with pycrate (APER); PFCP, GTPv2-C, GTP-U and Diameter headers and information elements
are decoded with Python struct parsers; NAS messages are extracted from NGAP and decoded per TS 24.501. The NGAP
Initial UE Message does not contain the SUPI: the subscriber identity is the SUCI inside the NAS Registration Request,
from which the IMSI is derived only for the null protection scheme (UERANSIM default)."

## §3.4.4 (engine)
"Per-source and per-interface state is kept in memory in sliding windows; PFCP SEIDs, UPF uplink TEIDs, smContextRefs
and policy identifiers learned from live traffic are persisted in SQLite so that sessions created before a restart are
not treated as unknown. Score S = S_base x w_recency x w_frequency (0-100): w_recency = 1.0 for events up to 5 s old and
decays to 0.5 with a 30 s time constant; w_frequency = 1 + min(1, count/reference - 1), plus 0.25 for each other
interface with an anomaly for the same SUPI (or source address) in the last 60 s, capped at 2.0."
Rule notes for Table 3.2: T02 = SM-context request from a non-AMF caller (User-Agent) or an unknown smContextRef;
T04 = same IMSI (null-scheme SUCI) registering through different gNBs within 60 s; T06 compares the packet rate of each
interface with a learned baseline (x5) and an absolute floor (SBI counts requests only); T08 compares NRF registry
snapshots and requires a duplicate NF instance to persist for 60 s; T09 requires a GTP-U sensor on the UPF VM.
Extensions: X01 NAS failure burst, X02 identity-request flood, X03 coordinated multi-interface flood.

## §3.4.5 (alert manager)
"The Alert Manager runs inside the NWDAF (port 8090, token-protected): GET /alerts (paginated, filters), GET /alerts/{id},
GET /stats, POST /rules/{id}/threshold, POST /mitigations/{id}/rollback. Alerts and the mitigation log are stored in
SQLite. CRITICAL alerts trigger Module 4; WARNING and CRITICAL alerts are POSTed to a configurable webhook."

## Table 3.4 (mitigation) -> replace by what is implemented
| Threat | Action | Reversible |
|---|---|---|
| T01, T08 | NRF: DELETE the rogue/flooding NF instance by nfInstanceId (only instances not established before the event) | yes: PUT of the saved profile |
| T02, T04 | SMF: release the SM context by smContextRef (when known) | no |
| T03, T05, T06, T07, T09, T10, X* | operator notification (+ webhook); PFCP deletion, iptables rate limiting and PCF throttling are future work: the NWDAF cannot send PFCP as the SMF, and on the Core VM all NFs share 127.0.0.1 and the NRF port, so iptables cannot single out one NF | n/a |
Default mode is dry-run (`MITIGATION_MODE=dry_run`; `off` / `enforce` available at runtime).

## §3.4.7 (containerisation)
"Redis, the NWDAF/IDRS service and one container per parser run with Docker Compose on the Core VM; the GTP-U sensor runs
on the UPF VM (docker-compose.sensor.yml) and reaches an authenticated Redis. The Grafana/InfluxDB stack of the original
design is replaced by the built-in dashboard served at /ui."

## §3.2.6 (NSSF)  Bind the NSSF to 127.0.0.14:7777 (Open5GS default) or add a capture for 192.168.56.10:7776;
otherwise NSSF traffic is outside the planned `tcp port 7777` on `lo` filter.
## Cover vs certificate  Use one title.
