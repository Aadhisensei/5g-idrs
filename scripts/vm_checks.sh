#!/usr/bin/env bash
# Run on the CORE VM after `docker compose up --build -d`, in dry_run, with one UE attached.
# Usage: TOKEN=<token from `docker compose logs nwdaf | grep token`> ./scripts/vm_checks.sh
set -u
TOKEN=${TOKEN:?set TOKEN (see: docker compose logs nwdaf | grep "control token")}
API=${API:-http://127.0.0.1:8090}; H="X-API-Token: $TOKEN"
ok(){ printf "  [ OK ] %s\n" "$1"; }; bad(){ printf "  [FAIL] %s\n" "$1"; FAILS=$((FAILS+1)); }; FAILS=0
J(){ curl -s -H "$H" "$API$1"; }
echo "1. NWDAF up, mitigation mode, NRF registry"
h=$(curl -s "$API/health"); echo "$h" | grep -q '"status": *"ok"' && ok "health ok" || bad "health"
echo "$h" | grep -q '"mitigation_mode": *"dry_run"' && ok "mitigation is dry_run" || bad "mitigation not dry_run"
n=$(echo "$h" | python3 -c 'import sys,json;print(json.load(sys.stdin)["nrf_registry"]["instances"])' 2>/dev/null || echo 0)
[ "${n:-0}" -gt 0 ] && ok "NRF registry readable ($n instances) -> T08 can work" || bad "nrf_registry.instances = 0 (NRF refused list/discovery; T08 disabled)"
echo "2. Does the NRF accept HTTP/2 prior knowledge (the mitigator's client)?"
./scripts/check_sbi.sh | sed 's/^/     /'
echo "3. Parser fields the new rules depend on (last 300 events)"
ev=$(docker compose exec -T redis sh -c 'redis-cli ${REDIS_PASSWORD:+-a "$REDIS_PASSWORD" --no-auth-warning} XREVRANGE ids:events + - COUNT 300')
ua=$(echo "$ev" | grep -o '"user_agent": "[^"]*"' | sort | uniq -c); loc=$(echo "$ev" | grep -c '"location": "http')
sid=$(echo "$ev" | grep -c '"stream_id": "[0-9]')
echo "$ua" | grep -qE 'AMF|SMF|PCF|UDM|AUSF|NRF|NSSF|BSF' && ok "user_agent carries caller NF types: $(echo "$ua" | tr -s ' ' | tr '\n' ';')" || bad "no caller NF in user_agent (only SCP/none) -> T02/T05/T07-caller rules stay silent"
[ "$loc" -gt 0 ] && ok "Location headers captured ($loc) -> smContextRef / policy ids learnable" || bad "no Location headers (attach a UE first; else T02 ref / T10 out-of-session stay silent)"
[ "$sid" -gt 0 ] && ok "stream_id present" || bad "no stream_id"
echo "$ev" | grep -q '"supi": "imsi-' && ok "SUPI present on events (null-scheme SUCI bound)" || bad "no SUPI on NAS/NGAP events (ECIES SUCI? T04 then silent)"
echo "4. Normal-traffic rates for T06 (attach/detach your UEs first)"
J /config/baseline | python3 -m json.tool | sed 's/^/     /'
echo "     -> set floors to ~1.5 x peak_pps:  curl -X PUT -H \"$H\" -d '{\"T06_FLOOR_SBI\": <n>}' $API/config/thresholds"
echo "5. After >=10 min idle + one attach/detach there must be NO alerts above INFO"
c=$(J "/alerts?tier=WARNING" | python3 -c 'import sys,json;print(json.load(sys.stdin)["total"])'); k=$(J "/alerts?tier=CRITICAL" | python3 -c 'import sys,json;print(json.load(sys.stdin)["total"])')
[ "$c" = 0 ] && [ "$k" = 0 ] && ok "no WARNING/CRITICAL alerts" || bad "WARNING=$c CRITICAL=$k -> inspect: curl -H '$H' $API/alerts?tier=WARNING"
echo "6. T08 test (stays dry_run): docker kill -s KILL <an NF>, restart it; no T08 must fire within ${T08_GRACE:-60}s,"
echo "   and a SECOND registered instance of an NF type must raise T08 only after the grace period."
echo; [ $FAILS -eq 0 ] && echo "ALL CHECKS PASSED" || echo "$FAILS check(s) failed"; exit $FAILS
