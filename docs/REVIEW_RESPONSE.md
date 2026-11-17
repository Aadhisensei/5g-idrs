# Response to the Phase 3/4 review (28 Oct 2026)

Status: **fixed** (code + test), **mitigated** (safe default/limitation documented), **open**.
Tests: `tests/test_engine.py`, `tests/test_app.py`, `tests/test_tables.py` (run with `PYTHONPATH=.`).

| Review item | Status | What was done |
|---|---|---|
| 8.1 Dockerfile crashes (`No module named nwdaf`) | fixed | copies `nwdaf/`, `PYTHONPATH=/app`, `python -m nwdaf.app`, `__init__.py` added |
| 8.4 / 9.4 mitigation on by default | fixed | default `dry_run`; `off`/`dry_run`/`enforce`; env aliases `MITIGATION_ENABLED`, `MITIGATION_DRY_RUN` |
| 9.4 HTTP/1.1 client vs HTTP/2 SBI | fixed | httpx HTTP/2 prior knowledge (tested against an h2c stub); `scripts/check_sbi.sh` for the real NRF |
| 9.4 NRF discovery / JSON Patch | fixed | list-based lookup, fallback discovery with `target-nf-type` + valid requester; JSON Patch for suspend |
| 9.4 wrong identifiers (SUPI null, SEID as smContextRef, loopback IP) | fixed | an action runs only with the identifiers it needs, else recorded as `skipped` with the reason |
| 9.4 little real effect (PCF/UDM calls) | fixed | removed; only NRF suspend/delete and SMF release remain, other rules notify the operator |
| 9.4 consumer stalled 5 s on SMF | fixed | background worker + bounded queue |
| 9.4 no rollback, no auth | fixed | `POST /mitigation/{id}/rollback` (NRF delete/suspend); `X-API-Token` on every state-changing endpoint |
| 9.1 T06 false positives (127.0.0.1) | fixed | flags only non-loopback sources |
| 9.1 T07 false positives (SEID 0) | fixed | PFCP parser decodes F-SEID; UPF SEIDs learned from Establishment Responses; 120 s warm-up |
| 9.1 T01 counts UplinkNASTransport / two UEs | fixed | counts NGAP `InitialUEMessage` only |
| 9.2 T02/T09 NAS table | fixed | table corrected and verified against pycrate (`test_tables.py`) |
| 9.2 T04 no `nf_type` | mitigated | caller from `User-Agent` (`fields.user_agent`); silent if the header is absent. **Verify on real traffic** |
| 9.2 T08 reads GTPv2-C | mitigated | renamed GTPv2-C signalling flood (legacy path); N3 GTP-U is not visible from the core VM |
| 9.2 T10 SUPI-based | fixed | replaced by multi-interface correlation (no SUPI needed); thresholds above a 6-UE legit burst |
| 9.3 NGAP table wrong | fixed | pycrate's own message name used; verified fallback map |
| 9.3 SCP double counting | fixed | volume counters skip the NF->SCP hop (`IDRS_SCP_IP`) |
| 9.3 streams unbounded | fixed | all streams capped (`IDS_STREAM_MAXLEN`, default 20000) |
| 9.3 consumer replays from 0 | fixed | resumes from `nwdaf:last_id` (`NWDAF_START=resume|beginning|latest`); stale alerts never mitigated |
| 9.3 active threats never expire | fixed | 10 min TTL, cap 500, per-rule cooldown |
| 9.3 alert history in memory only | fixed | SQLite (`/data/idrs.db`, mounted from `./data`), restored on start |
| 10 thesis: SQLite, threshold endpoint, rollback endpoint, dry-run flag | fixed | `GET/PUT /config/thresholds`, rollback, SQLite, `MITIGATION_DRY_RUN` |
| 10 thesis: rule table, 0-100 scoring (S_base x w_recency x w_frequency), INFO/WARNING/CRITICAL tiers | **open** | needs the Chapter 3 definitions (per-rule S_base, weight functions, tier cut-offs) |
| 10 thesis: iptables / PFCP deletion actions, separate alert-manager service on 8080, scapy parsers | **open** | design differs on purpose (in-NWDAF, pyshark/pycrate); update the thesis or decide to change |
| Remaining | open | smContextRef capture (T07 `terminate_session` stays skipped), SUPI correlation for NGAP/NAS/PFCP, nothing validated against live Open5GS |

## Second review (29 Oct 2026, section 12.4 / 12.6) and the thesis
| Item | Status | What was done |
|---|---|---|
| 12.4 #1 enforcement impossible on real traffic (T06 never fires, loopback sources) | fixed | rogue NF is now found by NRF-registry conflict (T08) and rejected by **nfInstanceId** (not IP); T01 only touches ids not established in the registry |
| 12.4 #1 smContextRef not captured | partly | SBI parser now emits `location`, `conn`, `stream_id`; engine learns smContextRef / policy ids from `Location`; session release still needs VM validation |
| 12.4 #2 T05/T10 fire on 12-15 UE registrations | fixed | per-NF thresholds raised (200 reads / 40 distinct SUPIs per 30 s), SCP second hop skipped, X03 now relative to a learned baseline; tests cover 12 and 15 UEs |
| 12.4 #3 reads open on 0.0.0.0 | fixed | every route except `/`, `/ui` (page shell) and `/health` needs the token (`IDRS_PROTECT_READS=false` to relax); SSE accepts `?token=` |
| 12.4 SUPI missing on NGAP/NAS/PFCP | partly | NAS parser derives the IMSI from a null-scheme SUCI; NGAP events inherit it via (gNB, RAN UE NGAP ID). PFCP events still have no subscriber id |
| 12.6 scoring / tiers | fixed | 0-100 score `S_base x w_recency x w_frequency`; INFO/WARNING/CRITICAL |
| 12.6 rule relabelling | fixed | thesis T01-T10; code-only rules are X01-X03 (extensions) |
| 12.6 alert-manager API, SQLite, rollback, dry-run | fixed | `/alerts` (paginated), `/alerts/{id}`, `/rules/{id}/threshold`, `/mitigations/{id}/rollback`, SQLite, `MITIGATION_DRY_RUN` |
| 12.6 thesis text vs code | open (your text) | see `docs/THESIS_REVIEW.md` section A |
| not done | open | InfluxDB/Grafana, iptables / PFCP-deletion actions (not feasible as specified), body-based T02, GTP-U data on the Core VM |

## Third review (30 Oct 2026, section 13)
| Item | Status | What was done |
|---|---|---|
| 13.4 #1 T08 flags the restarted NF | fixed | a duplicate singleton NF must persist `T08_GRACE` (60 s) before alerting; a stale entry that the NRF expires never alerts; ambiguous duplicates (already in the baseline) alert **without instance ids** so nothing can be auto-deleted; the mitigator re-checks the instance still exists |
| 13.4 #2 state rules fire on sessions that predate the IDS | fixed | SEIDs, UL TEIDs, smContextRefs, policy ids and first-seen time are persisted in SQLite and restored; first run after an upgrade replays the capped stream learn-only (no alerts) |
| 13.4 #3 Redis unauthenticated, no sensor entry | fixed | `REDIS_PASSWORD` in every client, Redis `--bind`/`--requirepass` in compose, `scripts/redis_firewall.sh`, `docker-compose.sensor.yml` for the UPF VM; **T09 is OFF by default** (`PUT /config/rules {"T09": true}`) |
| 13.4 #4 T06 noisy at start-up / bulk | fixed | SBI has its own floor (`T06_FLOOR_SBI`=30 req/s) and counts requests only (no responses, no SCP hop); `GET /config/baseline` shows observed peak pps for tuning; T05 reads raised to 300 / 30 s. The 25-events-per-UE density is still an estimate: measure it with `scripts/vm_checks.sh` |
| 13.5 NAS "undecoded (ciphered)" is readable under NEA0 | fixed | protected NAS: the inner plain message is decoded when it is plausibly plaintext (EPD 0x7E, security header 0, known type); real ciphertext is not mis-decoded (2000-payload test) |
| 13.5 tests need hypercorn/fakeredis, not listed | fixed | `tests/requirements.txt`, `tests/run_all.sh` |
| 13.6 #1,#3,#4 checks on the VM | tooling | `scripts/vm_checks.sh` runs the checks (health, registry, HTTP/2, user_agent, Location, SUPI, rates, idle alerts) |
| 13.6 #5 update the thesis | tooling | `docs/THESIS_TEXT_FIXES.md` has paste-ready replacement text; evaluation numbers must come from Phase 5 |
| Still not verified | open | user_agent / location / stream_id on real traffic; T04 needs null-scheme SUCI; T07 allow-list vs Open5GS paths |
