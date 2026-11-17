"""Parser tests on spec-built bytes (no live traffic needed). Run: PYTHONPATH=. python3 tests/test_parsers.py"""
import importlib.util, os, struct, sys
def load(p, n):
    spec = importlib.util.spec_from_file_location(n, p); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m); return m
res = []
def check(name, cond, extra=""):
    print(f"{'PASS' if cond else 'FAIL'}  {name} {extra}"); res.append(bool(cond))

nas = load("parsers/nas/parser.py", "nasp")
suci = bytes([0x01, 0x99, 0xF9, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10])   # imsi-999700000000001, null scheme
reg = bytes([0x7E, 0x00, 0x41, 0x79]) + len(suci).to_bytes(2, "big") + suci
r = nas.decode_nas(reg)
check("NAS Registration Request: null-scheme SUCI -> imsi-999700000000001", r["msg_type"] == "Registration Request" and r["supi"] == "imsi-999700000000001")
e1 = bytes([0x01, 0x99, 0xF9, 0x07, 0x00, 0x00, 0x01, 0x01]) + os.urandom(40)
r = nas.decode_nas(bytes([0x7E, 0x00, 0x41, 0x79]) + len(e1).to_bytes(2, "big") + e1)
check("NAS: ECIES-protected SUCI yields no (false) SUPI", r["identity_type"] == "SUCI" and "supi" not in r)
# security-protected NAS: EPD | sec hdr | MAC(4) | SQN | inner plain message
smc = bytes([0x7E, 0x00, 0x5E, 0x77, 0x00])                       # inner: Security Mode Complete
for hdr, label in ((0x01, "integrity protected"), (0x02, "integrity + NEA0"), (0x04, "new context + NEA0")):
    r = nas.decode_nas(bytes([0x7E, hdr]) + b"\xAA\xBB\xCC\xDD" + b"\x05" + smc)
    check(f"NAS {label}: inner message decoded (review 13.5)", r["decoded"] and r["msg_type"] == "Security Mode Complete" and r["inner_decoded"] and r["security_header_type"] == hdr)
bad = 0
for _ in range(2000):
    r = nas.decode_nas(bytes([0x7E, 0x02]) + os.urandom(30))
    bad += bool(r.get("decoded"))
check("NAS: genuinely ciphered payloads are not mis-decoded", bad <= 3, f"({bad}/2000 random payloads decoded)")
idr = bytes([0x7E, 0x00, 0x5C]) + (len(suci)).to_bytes(2, "big") + suci
check("NAS Identity Response carries the identity", nas.decode_nas(idr).get("supi") == "imsi-999700000000001")

pf = load("parsers/pfcp/parser.py", "pfcpp")
fteid = struct.pack("!HH", 21, 9) + b"\x01" + struct.pack("!I", 0xABCD) + bytes([192, 168, 56, 20])
pdr = struct.pack("!HH", 56, 2) + b"\x00\x01" + fteid
body = struct.pack("!HH", 19, 1) + b"\x01" + struct.pack("!HH", 57, 13) + b"\x02" + struct.pack("!Q", 3599) + bytes([10, 0, 0, 1]) + struct.pack("!HH", 8, len(pdr)) + pdr
hdr = bytes([0x21, 51]) + struct.pack("!H", len(body) + 12) + struct.pack("!Q", 0x1111) + b"\x00\x00\x01\x00"
o = pf.parse_pfcp_header(hdr + body)
check("PFCP Establishment Response: UPF F-SEID and uplink TEID", o["msg_type"] == "Session Establishment Response" and o["fseid"] == "3599" and o["ul_teids"] == [0xABCD])

gt = load("parsers/gtpu/parser.py", "gtpup")
g = gt.parse_gtpu(bytes([0x30, 0xFF]) + struct.pack("!H", 20) + struct.pack("!I", 0xABCD) + b"\x45" * 20)
check("GTP-U G-PDU header", g["msg_type"] == "G-PDU" and g["teid"] == 0xABCD and gt.parse_gtpu(b"\x00" * 8) is None)

import redis, common.redis_client as rc
os.environ["REDIS_PASSWORD"] = "pw"; c = rc.get_redis()
check("REDIS_PASSWORD is used by every client", c.connection_pool.connection_kwargs.get("password") == "pw")
print("\nALL PASS" if all(res) else "\nSOME FAILED"); sys.exit(0 if all(res) else 1)
