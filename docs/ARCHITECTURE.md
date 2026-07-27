# Architecture notes

## Why network_mode: host

Docker's default bridge network gives every container a private veth pair
and its own network namespace. Parsers need to see:
- the VM's real loopback interface (`lo`), where all SBI/HTTP2 traffic
  between NFs actually flows (every NF's SBI binds to `127.0.0.x:7777`)
- the VM's real LAN NIC, where PFCP and NGAP traffic to the UPF and gNB
  VMs is visible

A bridge network's private loopback is not the host's loopback, so SBI
capture would see nothing. `network_mode: host` puts every container in
the host's network namespace directly, at the cost of losing Docker's
network isolation between the parser containers (acceptable here since
this stack is single-purpose and deployed on a dedicated core VM).

## Why Redis Streams as the event bus

Chapter 3 specifies a "shared Redis Streams channel (ids:events)" for
exactly this reason: independent parser processes, no shared state, and
consumer-group semantics available later (e.g. if the Threat Evaluation
Engine in Phase 2 needs multiple consumers or replay-from-offset).

## Event schema

See `common/events.py`. Every parser publishes the same shape regardless
of protocol: `parser`, `interface`, `msg_type`, `src_ip`, `dst_ip`,
`supi`, `session_id`, `fields` (protocol-specific dict), `timestamp`,
`event_id`. This is what lets the Phase 2 Threat Evaluation Engine
correlate across interfaces by SUPI without protocol-specific logic.

## Known gaps going into Phase 2

1. NGAP decode needs validation against a real capture (see README).
2. NAS decode only works pre-security (unciphered). This is a hard
   limitation of passive monitoring without NAS key material, not
   something Phase 2 can fix — the Threat Evaluation Engine's rules
   involving NAS (e.g. registration abuse, T04) should be designed to
   rely primarily on the NGAP-layer signals (Initial UE Message
   frequency, RAN/AMF UE NGAP IDs) rather than deep NAS content.
3. SUPI extraction on the SBI parser is a coarse `imsi-`/`suci-` URL
   token scan, not a full JSON body parse. Good enough for T01/T07/T08
   but will need to read PATCH/POST bodies for richer correlation later.
