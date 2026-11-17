# Known gaps (validate on testbed)

- Mitigation defaults to `dry_run`. Switch: `POST /mitigation/mode/{off|dry_run|enforce}`.
- Fully actionable today: T06 (NRF lookup by source IP + DELETE). Others are skipped/notify-only until
  identifiers exist: SUPI is not populated by NGAP/NAS/PFCP parsers (SUCI is concealed), and a PFCP SEID
  cannot yet be mapped to an SMF smContextRef (capture the `Location` header of
  `POST /nsmf-pdusession/v1/sm-contexts` in the SBI parser).
- NRF/SMF request shapes follow TS 29.510/29.502 and were tested only against a stub; verify on Open5GS.
- On loopback every NF appears as 127.0.0.1, so SBI rules identify the caller via the `User-Agent` header
  (`fields.user_agent`). If Open5GS does not send it, T04 stays silent by design. T06 flags only non-loopback sources.
- T07 has a 120 s warm-up (`IDRS_T07_WARMUP_SEC`): sessions created before the IDS started are unknown.
- Thresholds are testbed-scale; tune in `threat_engine.py`.
- GTP: `parser-gtpv2c` is GTPv2-C (S11, EPC). A 5G SA core has no GTPv2-C; T08 only covers that legacy path.

# Live dashboard
- Open `http://<core-vm-ip>:8090/ui` (e.g. http://192.168.56.10:8090/ui). Served by the NWDAF; no extra container.
- Data path: parsers -> Redis -> NWDAF -> engine/alert manager/mitigator -> `/stream` (Server-Sent Events). Nothing simulated.
- Table is rate-limited to 40 events/s; charts, counters and rates are exact (computed per second on the server).
- History replayed from Redis at start-up is counted as "replayed", never shown as live traffic/rates.
- The mode switch, Resolve and Rollback buttons call the real REST endpoints. State-changing endpoints need `X-API-Token` (set `IDRS_API_TOKEN`, or read the generated token from `docker compose logs nwdaf`); the page asks for it once per session. Read endpoints stay open.
- Chart drawing (canvas) was not pixel-verified here; data flow, DOM updates and controls were tested end-to-end.

# After the thesis alignment
- Fields the new rules rely on were built to the spec and tested with synthetic input, but NOT yet seen on real Open5GS traffic:
  `fields.user_agent`, `fields.location`, `fields.stream_id/conn` (pyshark names `headers_user_agent`, `headers_location`, `streamid`).
  Check: `docker compose exec redis redis-cli XREVRANGE ids:events + - COUNT 300 | grep -o '"location": "[^"]*"' | head`.
- NRF registry polling (T08, T01 baseline) needs the NRF to allow `GET /nnrf-nfm/v1/nf-instances` or discovery; `/health` shows `nrf_registry.instances`.
- T07 allow-list (`KNOWN_SERVICES` in `threat_engine.py`) is generous but may need Open5GS-specific paths; run idle for 10 minutes and read `/alerts?rule_id=T07`.
- Dashboard and every API route need the token now (printed in the NWDAF log, or set `IDRS_API_TOKEN`).

# After the third review
- T09 is disabled by default. To use it: set `REDIS_PASSWORD` and `REDIS_BIND` in `.env`, run `scripts/redis_firewall.sh`, start the sensor on the UPF VM
  (`docker-compose.sensor.yml`), then `PUT /config/rules {"T09": true}`.
- T08 waits 60 s (`T08_GRACE`) by design; lower it only if your NRF expires dead NFs faster.
- State learned before the very first start cannot be known: attach UEs only after the IDS has been running for `IDRS_WARMUP_SEC` (120 s).
- Run `scripts/vm_checks.sh` after every deployment; keep MITIGATION_MODE=dry_run until it reports no WARNING/CRITICAL alerts at idle.
