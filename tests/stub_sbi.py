"""Tiny HTTP/2-cleartext stand-in for NRF + SMF (run with: hypercorn tests.stub_sbi:app --bind 127.0.0.1:PORT).
STUB_NO_LIST=1 makes the NF-list endpoint 404 so the discovery fallback is exercised."""
import asyncio, json, os
nfs = {"aaa": {"nfInstanceId": "aaa", "nfType": "AMF", "ipv4Addresses": ["127.0.0.5"], "nfStatus": "REGISTERED"},
       "bad": {"nfInstanceId": "bad", "nfType": "UDM", "ipv4Addresses": ["192.168.56.99"], "nfStatus": "REGISTERED"}}
async def app(scope, receive, send):
    if scope["type"] != "http": return
    body = b""
    while True:
        m = await receive(); body += m.get("body", b"")
        if not m.get("more_body"): break
    p, meth, q = scope["path"], scope["method"], scope.get("query_string", b"").decode()
    async def out(code, obj):
        await send({"type": "http.response.start", "status": code, "headers": [(b"content-type", b"application/json")]})
        await send({"type": "http.response.body", "body": json.dumps(obj).encode()})
    base = "/nnrf-nfm/v1/nf-instances"
    if meth == "GET" and p == base:
        return await out(404, {}) if os.environ.get("STUB_NO_LIST") else await out(200, {"_links": {"item": [{"href": f"{base}/{k}"} for k in nfs]}})
    if p.startswith(base + "/"):
        k = p.rsplit("/", 1)[1]
        if meth == "GET": return await out(200 if k in nfs else 404, nfs.get(k, {}))
        if meth == "DELETE": nfs.pop(k, None); return await out(204, {})
        if meth == "PUT": nfs[k] = json.loads(body or b"{}"); return await out(201, nfs[k])
        if meth == "PATCH":
            for op in json.loads(body or b"[]"):
                if op["path"] == "/nfStatus" and k in nfs: nfs[k]["nfStatus"] = op["value"]
            return await out(204, {})
    if meth == "GET" and p == "/nnrf-disc/v1/nf-instances":
        t = dict(x.split("=") for x in q.split("&") if "=" in x).get("target-nf-type")
        return await out(200, {"nfInstances": [v for v in nfs.values() if v["nfType"] == t]})
    if meth == "POST" and p.endswith("/release"):
        await asyncio.sleep(2.0); return await out(204, {})          # slow SMF
    if p == "/__state": return await out(200, nfs)
    await out(404, {})
