#!/usr/bin/env bash
# Run on the Core VM BEFORE enabling mitigation: does the NRF accept HTTP/1.1 or only HTTP/2 (prior knowledge)?
NRF=${1:-127.0.0.10:7777}
echo -n "HTTP/1.1            : "; curl -s -o /dev/null -w "%{http_code}\n" --max-time 3 "http://$NRF/nnrf-nfm/v1/nf-instances"
echo -n "HTTP/2 prior-knowl. : "; curl -s -o /dev/null -w "%{http_code}\n" --max-time 3 --http2-prior-knowledge "http://$NRF/nnrf-nfm/v1/nf-instances"
echo "The mitigator speaks HTTP/2 prior knowledge (httpx http1=False). 200 on the second line = it can reach the SBI."
