# Thesis review (Chapters 1-5, May 2026) and how the code now matches it

## A. Mistakes / inconsistencies in the thesis text
| # | Where | Problem | Suggested fix |
|---|---|---|---|
| 1 | §3.2.1 vs Figs 4.1, 4.2 | Text says UERANSIM **v3.2.7**; both terminal screenshots print **v3.2.8**. | Use v3.2.8 (or re-take the screenshots). |
| 2 | §3.3 step 2 | "5G-AKA via the AUSF and UDM **(N8)**". N8 is AMF-UDM (as in Table 1.1); authentication runs AMF-AUSF (**N12**) and AUSF-UDM (**N13**). | Write "(N12, N13)"; add N12/N13 to Table 1.1. |
| 3 | §3.2.3 vs Fig 4.2 | Text: NAS algorithms **NIA2 and NEA2**. The UE log shows `Selected integrity[2] ciphering[0]`, i.e. **NEA0 (no ciphering)**. | State the real configuration. It matters for the IDS: with NEA0 every NAS PDU is readable; with NEA2 only the pre-security messages (Registration Request, Identity, Authentication) are. |
| 4 | Cover vs Certificate | Two different titles ("...for 5G Core" vs "...served as a microservice of NWDAF for 5G Core Networks"). | Use one title. |
| 5 | Abstract, §1.1, §3.4.1, §4.1, §5.2 | "Parsers/modules have not been implemented". | Update once the implementation chapter exists (parsers, engine, alert manager, mitigator, dashboard are built). |
| 6 | §3.4.3 | Technologies differ from what was built: Scapy+hyper-h2 -> **pyshark/tshark** (HPACK dynamic tables need the connection start), pyasn1 -> **pycrate** (APER), "custom Scapy PFCP dissector" -> struct-based parser. "SUPI in Initial UE Messages": the InitialUEMessage carries a **SUCI** inside the NAS PDU, not a SUPI. | Describe what was built. The IMSI is recoverable only for the null protection scheme (UERANSIM default); with ECIES SUCIs rule T04 cannot see "the same IMSI". |
| 7 | §3.4.4 | State "in Redis hashes with TTLs" -> built in memory (sliding windows) + SQLite for alerts. | Update or move state to Redis. |
| 8 | §3.4.7, Table 3.3 | InfluxDB and Grafana are specified; the built dashboard (`/ui`) replaces Grafana, InfluxDB is not used. | Update or list as future work. |
| 9 | §3.2.6 | NSSF SBI at `192.168.56.10:7776`. The planned capture filter is `tcp port 7777` on `lo`, so NSSF traffic is invisible to the IDS. | Bind the NSSF to loopback `127.0.0.14:7777` (Open5GS default) or add a capture for 7776. |
| 10 | Table 3.4 | "iptables" for T01/T08/T05: on the Core VM all NFs appear as 127.0.0.1 and share the NRF port 7777, so iptables cannot block or rate-limit a single NF. "PFCP Session Deletion Request to the UPF" is rejected by the UPF unless sent by its associated SMF. | Describe the SBI actions actually used (NRF delete/suspend with rollback, SMF release). |
| 11 | Table 3.2 T02 | "SUPI in SM context from unexpected AMF/SMF" needs the JSON body (`supi`, `servingNfId`), which the SBI parser does not read. | Implemented variant: SM-context call by a non-AMF caller (User-Agent) or an unknown smContextRef (from the `Location` header). |
| 12 | Table 3.2 T09, §3.4.2 | GTP-U (N3) runs gNB<->UPF and never reaches the Core VM. | Deploy `parsers/gtpu` on the UPF VM (REDIS_HOST -> Core VM) and say so. |
| 13 | §3.4.5 | REST API on port 8080 / separate service. | Built inside the NWDAF on 8090 (`/alerts`, `/alerts/{id}`, `/stats`, `/rules/{id}/threshold`, `/mitigations/{id}/rollback` all exist). |

Correction on my side: earlier I said Open5GS ships an NWDAF. It does not; your §3.4.1 is right.

## B. Rule table: thesis vs code
Scoring and tiers follow §3.4.4 / Table 3.3: `S = S_base x w_recency x w_frequency` (0-100), INFO <40, WARNING 40-69, CRITICAL >=70; only CRITICAL triggers Module 4, WARNING also POSTs to `IDRS_WEBHOOK_URL`.

| Thesis rule (base) | Code | Data it needs | Status |
|---|---|---|---|
| T01 NF Registration Flood (70) | `T01` | SBI PUT /nnrf-nfm; NRF registry for which ids are established | tested synthetic |
| T02 Session Hijack (85) | `T02` (variant, see #11) | User-Agent, Location header | needs VM check |
| T03 PFCP Manipulation (80) | `T03` | PFCP F-SEID | tested synthetic + spec-built packets |
| T04 Registration Abuse (75) | `T04` | NAS SUCI (null scheme), gNB IP | tested synthetic |
| T05 UDM Exfiltration (65) | `T05` | SBI reads + User-Agent | tested synthetic |
| T06 Signalling Flood (60) | `T06` | per-interface PPS vs learned baseline | tested synthetic |
| T07 Unauthorized API (55) | `T07` | 3GPP service allow-list, caller matrix | tested synthetic; allow-list may need additions for Open5GS paths |
| T08 Rogue NF (90) | `T08` | NRF registry polling (`nwdaf/nrf_registry.py`) | tested against an h2c stub |
| T09 GTP Abuse (80) | `T09` | GTP-U sensor on the UPF VM | inert on the Core VM alone |
| T10 PCF Tampering (70) | `T10` | npcf-* paths, Location header | needs VM check |
| (extension) | `X01` NAS failure burst, `X02` identity-request flood, `X03` coordinated multi-interface flood | | tested synthetic |

Cross-interface temporal correlation (thesis: same SUPI, 60 s) is implemented as score corroboration: +0.25 on `w_frequency` per other interface that raised an anomaly for the same SUPI (or source IP when no SUPI) within 60 s. NGAP events inherit the SUPI bound from the NAS Registration Request of the same UE (gNB + RAN UE NGAP ID).
