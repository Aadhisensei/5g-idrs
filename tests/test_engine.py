"""Thesis-rule tests (T01-T10, scoring, tiers) on synthetic events. Run: PYTHONPATH=. python3 tests/test_engine.py"""
from common.events import IDRSEvent
from nwdaf.threat_engine import ThreatEngine

T0, CORE, UPF, GNB, GNB2 = 1_000_000.0, "192.168.56.10", "192.168.56.20", "192.168.56.30", "192.168.56.31"
def ev(parser, iface, msg, t, src=GNB, dst=CORE, supi=None, sid=None, **f):
    return IDRSEvent(parser=parser, interface=iface, msg_type=msg, src_ip=src, dst_ip=dst, supi=supi,
                     session_id=sid, fields=f, timestamp=T0 + t)
def sbi(t, method, path, ua=None, dst="127.0.0.12", supi=None, **f):
    return ev("sbi_http2", "SBI", f"{method} {path}", t, "127.0.0.1", dst, supi, method=method, path=path, user_agent=ua, **f)

def run(events, eng=None, pre=None):
    fired = []
    eng = eng or ThreatEngine(alert_callback=fired.append)
    if eng.alert_callback.__name__ != "append": eng.alert_callback = fired.append
    for fn in (pre or []): fn(eng)
    for e in events: eng.evaluate(e, now=e.timestamp)
    return fired

res = []
def check(name, cond, extra=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}"); res.append(bool(cond))
ids = lambda f: sorted({t.rule_id for t in f})

LEGIT = {f"id-{n}": {"nfType": n, "nfInstanceId": f"id-{n}", "ipv4Addresses": ["127.0.0.5"]} for n in ("AMF", "SMF", "UDM", "NRF", "PCF")}

# ---------------------------------------------------------------- legitimate traffic
def ue(u, b, gnb=GNB):
    s = f"imsi-99970000000{u:04d}"
    return [ev("ngap","N2","InitialUEMessage",b,src=gnb,ran_ue_ngap_id=u),
            ev("nas","N1","Registration Request",b,src=gnb,supi=s,ran_ue_ngap_id=u),
            ev("ngap","N2","UplinkNASTransport",b+.3,src=gnb,ran_ue_ngap_id=u),
            ev("pfcp","N4","Session Establishment Request",b+1,src=CORE,dst=UPF,sid="0"),
            ev("pfcp","N4","Session Establishment Response",b+1.1,src=UPF,dst=CORE,sid="1",fseid=str(1000+u),ul_teids=[5000+u])] + \
           [x for k in range(4) for x in (sbi(b+.5+k*.1,"GET",f"/nudm-sdm/v2/{s}/sm-data","AMF",dst="127.0.0.200",supi=s),
                                         sbi(b+.51+k*.1,"GET",f"/nudm-sdm/v2/{s}/sm-data","SCP",supi=s))]
legit = ue(1, 0) + [sbi(3,"PATCH","/nnrf-nfm/v1/nf-instances/id-AMF","AMF",dst="127.0.0.10"),
                    ev("pfcp","N4","Session Modification Request",400,src=CORE,dst=UPF,sid="1001")]
check("legit attach + heartbeat + later modification -> silent", run(legit) == [])
for n in (12, 15):
    evs = [x for u in range(n) for x in ue(u, u * 25.0 / n)]
    check(f"legit mass registration of {n} UEs in 25 s -> silent (review 12.4 #2)", run(evs) == [])
check("two UEs registering together -> silent", run(ue(1,0)+ue(2,1)) == [])

# ---------------------------------------------------------------- T01
flood = [sbi(100+i*.1,"PUT",f"/nnrf-nfm/v1/nf-instances/fake-{i}","SMF",dst="127.0.0.10") for i in range(25)] + \
        [sbi(100+i*.1+.05,"PUT","/nnrf-nfm/v1/nf-instances/id-AMF","AMF",dst="127.0.0.10") for i in range(3)]
f = run(flood, pre=[lambda e: e.ingest_registry(LEGIT, now=T0)])
t = [x for x in f if x.rule_id == "T01"]
check("T01 NF registration flood", bool(t) and t[0].severity.value == "CRITICAL", f"(score {t[0].score if t else None})")
check("T01 evidence lists only NF instances unknown to the NRF registry",
      bool(t) and all(i.startswith("fake-") for i in t[0].evidence["nf_instance_ids"]))
check("T01 without registry baseline -> no instance ids for the mitigator", [x for x in run(flood) if x.rule_id=="T01"][0].evidence["nf_instance_ids"] == [])
check("legit boot (12 NF registrations) -> silent", run([sbi(i*.3,"PUT",f"/nnrf-nfm/v1/nf-instances/n{i}","AMF",dst="127.0.0.10") for i in range(12)]) == [])

# ---------------------------------------------------------------- T02
mk = lambda t, ua, path="/nsmf-pdusession/v1/sm-contexts": sbi(t,"POST",path,ua,dst="127.0.0.4")
check("T02 SM-context request from a non-AMF NF", ids(run([mk(1,"PCF")])) == ["T02"])
check("T02 AMF creating SM context is legitimate", run([mk(1,"AMF")]) == [])
learn = sbi(1,"POST","/nsmf-pdusession/v1/sm-contexts","AMF",dst="127.0.0.4")
learn.fields["location"] = "http://127.0.0.4:7777/nsmf-pdusession/v1/sm-contexts/9"
check("T02 release of an smContextRef never created (after warm-up)", ids(run([ev("ngap","N2","InitialUEMessage",0), learn, mk(300,"AMF","/nsmf-pdusession/v1/sm-contexts/77/release")])) == ["T02"])
check("T02 release of a known smContextRef is fine", run([ev("ngap","N2","InitialUEMessage",0), learn, mk(300,"AMF","/nsmf-pdusession/v1/sm-contexts/9/release")]) == [])

# ---------------------------------------------------------------- T03
est = ev("pfcp","N4","Session Establishment Response",2,src=UPF,dst=CORE,sid="4369",fseid="3599")
mod = lambda t, sid: ev("pfcp","N4","Session Modification Request",t,src=CORE,dst=UPF,sid=sid)
check("T03 unknown SEID after warm-up", ids(run([ev("ngap","N2","InitialUEMessage",0), est, mod(400,"777")])) == ["T03"])
check("T03 known UPF SEID passes", run([ev("ngap","N2","InitialUEMessage",0), est, mod(400,"3599")]) == [])
check("T03 silent during warm-up", run([ev("ngap","N2","InitialUEMessage",0), mod(5,"777")]) == [])

# ---------------------------------------------------------------- T04 + identity binding
reg = lambda t, gnb, s="imsi-999700000000001", ran=7: ev("nas","N1","Registration Request",t,src=gnb,supi=s,ran_ue_ngap_id=ran)
f = run([reg(0,GNB), reg(20,GNB2)])
check("T04 same IMSI registering via two gNBs", ids(f) == ["T04"] and f[0].severity.value == "CRITICAL", f"(score {f[0].score if f else None})")
check("T04 same gNB twice / different IMSIs -> silent", run([reg(0,GNB), reg(20,GNB)]) == [] and run([reg(0,GNB), reg(20,GNB2,"imsi-999700000000002")]) == [])
eng = ThreatEngine(); eng.evaluate(reg(0,GNB), now=T0); ng = ev("ngap","N2","UplinkNASTransport",1,ran_ue_ngap_id=7); eng.evaluate(ng, now=T0+1)
check("NGAP events inherit the SUPI bound from the NAS Registration Request", ng.supi == "imsi-999700000000001")

# ---------------------------------------------------------------- T05
harvest = [sbi(i*.5,"GET",f"/nudm-sdm/v2/imsi-99970000{i:07d}/sm-data","AMF",supi=f"imsi-99970000{i:07d}") for i in range(45)]
check("T05 UDM bulk read (45 distinct SUPIs / 30 s)", ids(run(harvest)) == ["T05"])
check("T05 SCP second hop is not counted", run([dict_ev for dict_ev in [sbi(i*.5,"GET",f"/nudm-sdm/v2/imsi-9{i:07d}/x","SCP",supi=f"imsi-9{i:07d}") for i in range(60)]]) == [])

# ---------------------------------------------------------------- T06 (+X03)
check("T06 flood on one interface (no baseline yet: absolute floor)", ids(run([ev("ngap","N2","InitialUEMessage",i*.02) for i in range(120)])) == ["T06"])
steady = lambda iface, par, pps, a, b: [ev(par, iface, "x", t + k/pps) for t in range(a, b) for k in range(pps)]
check("T06 baseline-relative: 18 pps over a 5 pps baseline is NOT a flood", run(steady("N4","pfcp",5,0,120) + steady("N4","pfcp",18,120,126)) == [])
f = run(steady("N4","pfcp",5,0,120) + steady("N4","pfcp",40,120,124))
check("T06 baseline-relative: 40 pps over a 5 pps baseline IS a flood", ids(f) == ["T06"], f"(baseline {f[0].evidence['baseline_pps'] if f else None} pps)")
two = [ev("ngap","N2","InitialUEMessage",i*.02) for i in range(120)] + [ev("pfcp","N4","Session Establishment Request",3+i*.02,src=CORE,dst=UPF) for i in range(120)]
check("X03 coordinated flood on two interfaces", ids(run(two)) == ["T06", "X03"])

# ---------------------------------------------------------------- T07
check("T07 not a 3GPP service", ids(run([sbi(1,"GET","/admin/backup","AMF")])) == ["T07"])
check("T07 method not defined for the service", ids(run([sbi(1,"DELETE","/nudm-ueau/v1/x/auth-events","AUSF")])) == ["T07"])
check("T07 caller NF does not consume the service", ids(run([sbi(1,"POST","/nausf-auth/v1/ue-authentications","PCF")])) == ["T07"])
check("T07 normal operations are silent", run([sbi(1,"GET","/nudm-sdm/v2/imsi-1/nssai","AMF"), sbi(2,"POST","/nausf-auth/v1/ue-authentications","AMF"),
      sbi(3,"POST","/nnrf-nfm/v1/nf-status-notify","NRF"), sbi(4,"POST","/namf-callback/v1/x","SMF")]) == [])
f = run([sbi(1,"GET","/admin","AMF")]); check("T07 single violation = 55 -> WARNING (not auto-mitigated)", f[0].score == 55.0 and f[0].severity.value == "WARNING")
f = run([sbi(i*5,"GET","/admin","AMF") for i in range(14)]); check("T07 repeated violations are corroborated -> CRITICAL", max(x.score for x in f) >= 70, f"(max {max(x.score for x in f)})")

# ---------------------------------------------------------------- T08 (grace period)
def reg_engine():
    e = ThreatEngine(); o = []; e.alert_callback = o.append; return e, o
eng, out = reg_engine()
eng.ingest_registry(LEGIT, now=T0); eng.ingest_registry(LEGIT, now=T0+10)
check("T08 unchanged registry -> silent", out == [])
two_udm = {**LEGIT, "evil-1": {"nfType": "UDM", "nfInstanceId": "evil-1", "ipv4Addresses": ["192.168.56.99"]}}
for dt in (20, 30, 50, 70): eng.ingest_registry(two_udm, now=T0+dt)
check("T08 duplicate UDM is NOT flagged before the grace period (review 13.4 #1)", out == [])
eng.ingest_registry(two_udm, now=T0+85)
check("T08 duplicate that persists past the grace period -> rogue = newcomer, CRITICAL", len(out) == 1 and out[0].evidence["nf_instance_ids"] == ["evil-1"] and out[0].severity.value == "CRITICAL", f"(score {out[0].score if out else None})")
eng, out = reg_engine()
stale = {**LEGIT, "amf-old": {"nfType": "AMF", "ipv4Addresses": ["127.0.0.5"]}}
restarted = {k: v for k, v in LEGIT.items() if k != "id-AMF"} | {"amf-old": stale["amf-old"], "amf-new": {"nfType": "AMF", "ipv4Addresses": ["127.0.0.5"]}}
eng.ingest_registry(stale, now=T0)
for dt in (10, 20, 30): eng.ingest_registry(restarted, now=T0+dt)          # stale + restarted AMF both listed
eng.ingest_registry({k: v for k, v in restarted.items() if k != "amf-old"}, now=T0+40)   # NRF expired the stale entry
for dt in (50, 100, 200): eng.ingest_registry({k: v for k, v in restarted.items() if k != "amf-old"}, now=T0+dt)
check("T08 AMF restart with a lingering stale entry -> no alert, live AMF never targeted", out == [])
eng, out = reg_engine()
dup = {"a": {"nfType": "UDM", "ipv4Addresses": ["127.0.0.12"]}, "b": {"nfType": "UDM", "ipv4Addresses": ["127.0.0.99"]}}
for dt in (0, 30, 70): eng.ingest_registry(dup, now=T0+dt)
check("T08 duplicates already present in the baseline snapshot -> alert WITHOUT instance ids (never auto-delete a guess)", len(out) == 1 and out[0].evidence["nf_instance_ids"] == [] and out[0].evidence["ambiguous"])
eng2, out2 = reg_engine(); eng2.ingest_registry(LEGIT, now=T0)
eng2.ingest_registry({**LEGIT, "id-UDM": {"nfType": "AMF", "ipv4Addresses": ["127.0.0.9"]}}, now=T0+30)
check("T08 nfType of an existing instance changed (immediate)", any("changed" in x.evidence["reason"] for x in out2))

# ---------------------------------------------------------------- T09
gp = lambda t, teid, dst=UPF: ev("gtpu","N3","G-PDU",t,src=GNB,dst=dst,teid=teid,count=30)
en9 = lambda e: e.set_rule_enabled("T09", True)
pre9 = [ev("ngap","N2","InitialUEMessage",0), ev("pfcp","N4","Session Establishment Response",2,src=UPF,dst=CORE,fseid="3599",ul_teids=[43981])]
check("T09 is OFF by default (needs the GTP-U sensor + authenticated Redis)", run(pre9 + [gp(400, 9999)]) == [])
check("T09 TEID without a PFCP session (after warm-up, rule enabled)", ids(run(pre9 + [gp(400, 9999)], pre=[en9])) == ["T09"])
check("T09 known TEID passes", run(pre9 + [gp(400, 43981)], pre=[en9]) == [])
check("T09 silent when no TEIDs are known yet / during warm-up", run([ev("ngap","N2","InitialUEMessage",0), gp(400, 9999)], pre=[en9]) == [] and run(pre9 + [gp(5, 9999)], pre=[en9]) == [])

# ---------------------------------------------------------------- T10
pol = lambda t, path, m="POST", ua="SMF": sbi(t, m, path, ua, dst="127.0.0.13")
check("T10 PCF policy-modification rate anomaly", ids(run([pol(i*.2,"/npcf-smpolicycontrol/v1/sm-policies/3/update") for i in range(35)])) == ["T10"])
check("T10 single policy create is silent", run([pol(1,"/npcf-smpolicycontrol/v1/sm-policies")]) == [])
lp = pol(1,"/npcf-smpolicycontrol/v1/sm-policies"); lp.fields["location"] = "http://127.0.0.13:7777/npcf-smpolicycontrol/v1/sm-policies/3"
check("T10 update of a policy never created (after warm-up)", ids(run([ev("ngap","N2","InitialUEMessage",0), lp, pol(300,"/npcf-smpolicycontrol/v1/sm-policies/42/update")])) == ["T10"])
check("T10 update of a known policy is fine", run([ev("ngap","N2","InitialUEMessage",0), lp, pol(300,"/npcf-smpolicycontrol/v1/sm-policies/3/update")]) == [])

# ---------------------------------------------------------------- extensions
check("X01 NAS failure burst", ids(run([ev("nas","N1","Authentication Failure",i*.5) for i in range(6)])) == ["X01"])
check("X02 identity request flood", ids(run([ev("nas","N1","Identity Request",i*.5,src=CORE,dst=GNB) for i in range(6)])) == ["X02"])

# ---------------------------------------------------------------- review 13.4 #2: state survives restart / replay
rows = []
engA = ThreatEngine(); engA.persist = lambda k, key, ts: rows.append((k, key, ts))
for e in [ev("ngap","N2","InitialUEMessage",0), ev("pfcp","N4","Session Establishment Response",2,src=UPF,dst=CORE,sid="1",fseid="3599",ul_teids=[43981]),
          (lambda x: (x.fields.__setitem__("location","http://127.0.0.4:7777/nsmf-pdusession/v1/sm-contexts/9"), x)[1])(sbi(3,"POST","/nsmf-pdusession/v1/sm-contexts","AMF",dst="127.0.0.4"))]:
    engA.evaluate(e, now=e.timestamp)
kinds = {k for k, _, _ in rows}
check("learned state is persisted (seid, ul_teid, smctx, first_ts)", {"seid", "ul_teid", "smctx", "meta"} <= kinds, f"({sorted(kinds)})")
late = mod(86400, "3599")        # a day later, after an NWDAF restart
engB = ThreatEngine(); fb = []; engB.alert_callback = fb.append; engB.restore_state(rows); engB.evaluate(late, now=late.timestamp)
check("after restart: modification of a session created before it -> silent (was T03 CRITICAL)", fb == [])
engC = ThreatEngine(); fc = []; engC.alert_callback = fc.append; engC.evaluate(ev("ngap","N2","InitialUEMessage",0), now=T0); engC.evaluate(late, now=late.timestamp)
check("control: without the restored state the same event IS flagged", ids(fc) == ["T03"])
engD = ThreatEngine(); fd = []; engD.alert_callback = fd.append
hist = [ev("ngap","N2","InitialUEMessage",0), ev("pfcp","N4","Session Establishment Response",2,src=UPF,dst=CORE,sid="1",fseid="3599")]
for h in hist: engD.learn_only(h)
engD.evaluate(late, now=late.timestamp)
check("learn-only replay of historical events: no alerts, state learned", fd == [] and engD._seids.get("3599") is not None and engD.stats()["evaluated"] == 1)
mk2 = sbi(300,"POST","/nsmf-pdusession/v1/sm-contexts/9/release","AMF",dst="127.0.0.4")
engE = ThreatEngine(); fe = []; engE.alert_callback = fe.append; engE.restore_state(rows); engE.evaluate(mk2, now=mk2.timestamp)
check("after restart: AMF release of a known smContextRef -> silent (was T02 CRITICAL)", fe == [])

# ---------------------------------------------------------------- review 13.4 #4: T06 floors / SBI request counting
one_attach = [sbi(i*0.025,"GET","/nudm-sdm/v2/imsi-1/x","AMF",dst="127.0.0.200") for i in range(20)] + \
             [sbi(i*0.025+.01,"GET","/nudm-sdm/v2/imsi-1/x","SCP") for i in range(20)] + \
             [ev("sbi_http2","SBI","response",i*0.025+.02,"127.0.0.12","127.0.0.1",status="200") for i in range(40)]
check("T06: one UE attach (80 SBI events in 2 s: requests, SCP hop, responses) -> silent", run(one_attach) == [])
dense = [x for u in range(20) for x in [sbi(u*1.25+k*.04,"GET","/nudm-sdm/v2/imsi-1/x","AMF",dst="127.0.0.200") for k in range(8)] +
         [sbi(u*1.25+k*.04+.01,"GET","/nudm-sdm/v2/imsi-1/x","SCP") for k in range(8)] +
         [ev("sbi_http2","SBI","response",u*1.25+k*.04+.02,"127.0.0.12","127.0.0.1",status="200") for k in range(9)]]
check("T06: 20 UEs attaching in 25 s at ~25 SBI events per UE -> silent (review 13.4 #4)", run(dense) == [])
flood_sbi = [sbi(i*0.005,"POST","/nnrf-nfm/v1/subscriptions","AMF",dst="127.0.0.10") for i in range(400)]
check("T06: a genuine SBI request flood (200 req/s) still fires", "T06" in ids(run(flood_sbi)))
check("T06: SBI has its own floor (20 req/s silent) while N2 uses the lower floor (20 pps fires)",
      run([sbi(i/20.0,"GET","/nudm-sdm/v2/x","AMF") for i in range(200)]) == [] and "T06" in ids(run([ev("ngap","N2","InitialUEMessage",i/20.0) for i in range(200)])))
engP = ThreatEngine(); [engP.evaluate(e, now=e.timestamp) for e in steady("N2","ngap",8,0,20)]
ps = engP.pps_stats()
check("pps_stats reports baseline/peak/floor for tuning", "N2" in ps and ps["N2"]["peak_pps"] >= 7 and ps["N2"]["floor_pps"] == 15.0, f"({ps.get('N2')})")
check("rules can be toggled at runtime", ThreatEngine().rules_state()["T09"] is False and ThreatEngine().set_rule_enabled("T09", True)["T09"] is True)

# ---------------------------------------------------------------- scoring + tiers (thesis 3.4.4 / Table 3.3)
f = run([reg(0,GNB), reg(20,GNB2)]); check("score = S_base x w_recency x w_frequency", f[0].evidence["score_parts"]["base"] == 75 and 0.5 <= f[0].evidence["score_parts"]["w_recency"] <= 1.0 and 1.0 <= f[0].evidence["score_parts"]["w_frequency"] <= 2.0)
eng = ThreatEngine(); out = []; eng.alert_callback = out.append
old = reg(0,GNB); eng.evaluate(old, now=T0); eng.evaluate(reg(20,GNB2), now=T0+20+600)
check("w_recency decays with event age -> tier drops (75 x 0.5 = 37.5 -> INFO)", out and out[0].score == 37.5 and out[0].severity.value == "INFO", f"(score {out[0].score if out else None})")
eng = ThreatEngine(); out = []; eng.alert_callback = out.append
eng.evaluate(ev("nas","N1","Authentication Failure",0,src=GNB), now=T0)
for i in range(6): eng.evaluate(ev("nas","N1","Authentication Failure",1+i*.3,src=GNB), now=T0+1+i*.3)
base_score = out[0].score
eng = ThreatEngine(); out = []; eng.alert_callback = out.append
for i in range(6): eng.evaluate(ev("nas","N1","Authentication Failure",i*.3,src=GNB), now=T0+i*.3)
for i in range(120): eng.evaluate(ev("ngap","N2","InitialUEMessage",1+i*.02,src=GNB), now=T0+1+i*.02)
sc = {(t.rule_id): t.score for t in out}
check("cross-interface correlation raises w_frequency for the same source", sc.get("T06", 0) > 60.0 and any(t.evidence["score_parts"]["w_frequency"] > 1.0 for t in out if t.rule_id == "T06"), f"({sc})")
check("tiers: INFO<40<=WARNING<70<=CRITICAL", [__import__('nwdaf.threat_models', fromlist=['x']).score_to_severity(x).value for x in (39.9, 40, 69.9, 70)] == ["INFO","WARNING","WARNING","CRITICAL"])

# ---------------------------------------------------------------- runtime thresholds
eng = ThreatEngine(); eng.set_rule_threshold("X01", 3); out = []; eng.alert_callback = out.append
for i in range(4): eng.evaluate(ev("nas","N1","Authentication Failure",i*.5), now=T0+i*.5)
check("runtime threshold per rule (thesis POST /rules/{id}/threshold)", len(out) == 1 and eng.get_thresholds()["X01_THRESH"] == 3)
try: eng.set_rule_threshold("T03", 1); check("rule without single numeric threshold is refused", False)
except ValueError: check("rule without single numeric threshold is refused", True)
print("\nALL PASS" if all(res) else "\nSOME FAILED"); raise SystemExit(0 if all(res) else 1)
