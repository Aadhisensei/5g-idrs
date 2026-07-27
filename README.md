# 5G Core IDRS — Phase 1: Custom NWDAF + Protocol Parsers

Microservice-based Intrusion Detection and Response System for the 5G Core,
built as a companion NWDAF microservice on an Open5GS testbed.
M.Sc. thesis project, Kerala University of Digital Sciences, Innovation and
Technology (DUK). Supervisor: Dr. Preetam Mukherjee.

> **Status**: this repo implements Module 1 (Protocol Parsers) and the
> custom NWDAF coordination service. The Threat Evaluation Engine, Tiered
> Alert Manager, and Attack Mitigation Module (Modules 2–4) are the next
> phases — see [Roadmap](#roadmap).

## Testbed topology

| VM        | IP              | Role                                   |
|-----------|-----------------|-----------------------------------------|
| 5G-Core   | 192.168.56.10   | Open5GS core NFs (no UPF), MongoDB, **this stack** |
| 5G-UPF    | 192.168.56.20   | Open5GS UPF                             |
| 5G-gNB    | 192.168.56.30   | UERANSIM gNB                            |
| 5G-UE     | 192.168.56.40   | UERANSIM UE                             |

This stack deploys **only on the 5G-Core VM**. It has visibility into
loopback SBI traffic (all NF-to-NF calls run on `127.0.0.x:7777`) and the
LAN interface carrying PFCP (SMF↔UPF, UDP/8805) and NGAP (gNB↔AMF,
SCTP/38412).

## Architecture

```
5G Core NFs (loopback + LAN)
        │
        ▼
┌─────────────────────────────────────────────┐
│  Module 1: Protocol Parsers (one container   │
│  each — a crash in one never affects others) │
│                                               │
│  sbi_http2 · pfcp · ngap · nas · gtpv2c ·     │
│  diameter                                    │
└───────────────────┬───────────────────────────┘
                     │ publish IDRSEvent JSON
                     ▼
              Redis Stream: ids:events
                     │
                     ▼
┌─────────────────────────────────────────────┐
│  Custom NWDAF microservice                   │
│  (Open5GS ships no NWDAF — this is it)       │
│  · consumes ids:events                       │
│  · rolling buffer + counters                 │
│  · REST API (loosely modeled on              │
│    Nnwdaf_AnalyticsInfo, TS 29.520)          │
└─────────────────────────────────────────────┘
```

Every parser is an independent container publishing a common event schema
(`common/events.py`) to the `ids:events` Redis stream. NAS is the one
exception: it has no IP-layer transport of its own (it rides inside NGAP),
so the NAS parser consumes a `nas:raw` stream fed by the NGAP parser
rather than sniffing a NIC directly.

## Parser implementation status

| Parser     | Interface | Method                                              | Status |
|------------|-----------|------------------------------------------------------|--------|
| sbi_http2  | SBI       | tshark/pyshark HTTP/2 dissection on `lo`             | Functional |
| pfcp       | N4        | Hand-decoded PFCP basic header (TS 29.244 §7.2)      | Functional |
| ngap       | N2        | `pycrate` APER decode, falls back to raw hex on failure | Provisional — not yet validated against a real testbed capture |
| nas        | N1        | Heuristic message-type lookup on plaintext (pre-security) NAS only | Functional for unciphered messages only |
| gtpv2c     | S11       | Basic header decode; not present in a pure 5G-SA testbed | Stub — expect silence |
| diameter   | S6a       | Fixed header decode; not present in a pure 5G-SA testbed | Stub — expect silence |

The NGAP decoder is the one genuinely unfinished piece — full APER
decoding needs to be cross-checked against a real Wireshark-dissected
capture from the testbed before its output is trusted for Phase 2 rule
development. Ciphered NAS (anything after Security Mode Complete) is
fundamentally unreadable to a passive monitor without the derived NAS
keys — this is a known, permanent limitation of this design, not a bug
to fix.

## Quick start (on the 5G-Core VM)

```bash
git clone <this-repo> 5g-idrs
cd 5g-idrs

# Detect the LAN interface carrying 192.168.56.0/24
./scripts/detect_interfaces.sh

# Build and start everything
docker compose up --build -d

# Watch parser output
docker compose logs -f parser-sbi parser-pfcp parser-ngap

# Trigger some traffic: from the UE VM, bring the UE up/down or
# re-run the PDU session establishment to generate NGAP/PFCP/SBI traffic
```

Verify the NWDAF is collecting:

```bash
curl http://127.0.0.1:8090/health
curl http://127.0.0.1:8090/stats
curl http://127.0.0.1:8090/events/recent?limit=20
curl http://127.0.0.1:8090/nnwdaf-analyticsinfo/v1/summary
```

## Repo layout

```
common/            shared IDRSEvent schema + Redis Streams helper
parsers/<name>/    one parser per protocol, each its own Dockerfile
nwdaf/             the custom NWDAF FastAPI service
scripts/           interface auto-detection for docker-compose
docs/              architecture notes
```

## Roadmap

- **Phase 1 (this repo)**: protocol parsers + NWDAF telemetry collection
- **Phase 2**: Threat Evaluation Engine — the ten detection rules (T01–T10),
  dynamic threat scoring, cross-interface temporal correlation via SUPI
- **Phase 3**: Tiered Alert Manager — SQLite persistence, REST API,
  INFO/WARNING/CRITICAL tiering
- **Phase 4**: Attack Mitigation Module — automated, reversible responses
  via PCF/SMF/NRF, dry-run mode

## Attribution

Design based on the microservice-based IDRS architecture proposed in this
thesis, extending the security-centric NWDAF approach of Nair et al.,
"Security-Centric NWDAF Module for Threat Detection and Mitigation in 5G
Core Networks" (ICISS 2025).
"# 5g-idrs" 
