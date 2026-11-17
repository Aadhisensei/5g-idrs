"""Verify hand-written NAS tables against pycrate's TS 24.501 definitions. PYTHONPATH=. python3 tests/test_tables.py"""
import importlib.util, os, re, sys, types
os.environ.setdefault("REDIS_HOST", "127.0.0.1")
from pycrate_mobile import TS24501_FGMM as MM
spec = importlib.util.spec_from_file_location("nasp", "parsers/nas/parser.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
norm = lambda s: re.sub(r"[^a-z]", "", s.lower())
bad = []
for code, name in m.MM_MSG_TYPES.items():
    cls = MM.FGMMTypeClasses.get(code)
    ref = norm(cls.__name__.replace("FGMM", "", 1)) if cls else None
    n = norm(name)
    n = re.sub(r"(deregistration(?:request|accept))ueoriginating", r"modeRegistration\1", n) if False else n
    if "ueoriginating" in n: n = "mo" + n.replace("ueoriginating", "")
    if "ueterminated" in n:  n = "mt" + n.replace("ueterminated", "")
    n = {"gmmstatus": "status"}.get(n, n)
    ok = ref is not None and n == ref
    if not ok: bad.append((hex(code), name, cls.__name__ if cls else None))
print("NAS 5GMM table vs pycrate:", "ALL MATCH" if not bad else f"MISMATCH {bad}")
sys.exit(1 if bad else 0)
