#!/usr/bin/env python3
"""
V3 TRIPLE SWEEP — ETHEREUM FORMS — 2026-10-21. Companion to v3_sweep.py
(which swept ~140k SHA-256 derivations, ZERO hits). This sweep re-runs
the same family structure with Keccak-256 (Ethereum's hash, original
0x01 padding — NOT NIST SHA3) plus Ethereum-specific encodings:
abi-style u256 selector encodings, ASCII-decimal selectors, and
Ethereum-address-derived candidates.

Targets (v3 commitment triple, sealed in Excalibur fork block 23606 and
in the Aether Proof payload; n = 0x7c2bac1d is a construction element):
    hp = 760515aafaed2fdc
    hq = 9d9097b3edf2f947
    hr = f2d890b337fb40d5

A "hit" = any single component matching its target under a fully
specified, re-runnable derivation (recorded verbatim in the results).
Phase 0 calibrates the harness against the OLD triple under the
original SHA-256 scheme before any negative here is trusted.

Pattern is taken from the messerene_operator module constant, never
from prose. Keccak is the pure-Python implementation pinned by test
vectors in aether-proof-public/lib/keccak.py.
"""
import hashlib, json, sys, time
sys.path.insert(0, "/home/hatch/workspace/your_files")
sys.path.insert(0, "/home/hatch/workspace/aether-proof-public/lib")
from messerene_operator import messerene, derive, mul, PATTERN, N, Gx, Gy
from keccak import keccak256

OLD = {"P": "5f655bd61a946c54", "Q": "a491c2683b267ab3", "R": "8dfe290f8dc993f5"}
V3 = {"hp": "760515aafaed2fdc", "hq": "9d9097b3edf2f947", "hr": "f2d890b337fb40d5"}
NV3 = 0x7C2BAC1D
PB = bytes.fromhex(PATTERN)
PRE = b"MESSERENE/PREGENESIS/v1"
SEL = b"MESSERENE/SEL="
NB_BE, NB_LE = NV3.to_bytes(4, "big"), NV3.to_bytes(4, "little")
OUT = "/home/hatch/workspace/your_files/v3-sweep-ethereum-results.json"

RESULTS = {"families": {}, "total_tried": 0, "calibration_ok": False}
FAM = {"name": None, "tried": 0, "hits": []}

def begin(name, detail):
    FAM["name"], FAM["tried"], FAM["hits"] = name, 0, []
    RESULTS["families"][name] = {"tried": 0, "hits": [], "detail": detail}
    print(f"--- {name}: {detail}", flush=True)

def end():
    RESULTS["families"][FAM["name"]]["tried"] = FAM["tried"]
    RESULTS["families"][FAM["name"]]["hits"] = FAM["hits"]
    RESULTS["total_tried"] = sum(f["tried"] for f in RESULTS["families"].values())
    with open(OUT, "w") as f:
        json.dump(RESULTS, f, indent=1)
    print(f"    done: {FAM['tried']} tried, {len(FAM['hits'])} hits", flush=True)

def check(derivation, h_hex):
    FAM["tried"] += 1
    for comp, target in V3.items():
        if h_hex == target:
            rec = {"component": comp, "value": h_hex, "derivation": derivation}
            FAM["hits"].append(rec)
            print(f"*** HIT {comp}: {h_hex}  via  {derivation}", flush=True)

def h_kec(k): return keccak256(k.to_bytes(32, "big"))[:8].hex()
def h_sha(k): return hashlib.sha256(k.to_bytes(32, "big")).hexdigest()[:16]
def wrap(x): return (int.from_bytes(x, "big") % (N - 1)) + 1

# k-derivation schemes (selector encoding appended per scheme layout)
def k_1a(enc, pmat=PB, dom=PRE):   # keccak256(dom || Pmat || SEL || enc)
    return wrap(keccak256(dom + pmat + SEL + enc))
def k_1b(enc, pmat=PB):            # keccak256(SEL || enc || Pmat) — structural mirror of messerene()
    return wrap(keccak256(SEL + enc + pmat))
def k_sha(enc, pmat=PB):           # original: sha256(SEL || enc || Pmat) == messerene(PATTERN, SEL||enc)
    return wrap(hashlib.sha256(SEL + enc + pmat).digest())

ENCS_FULL = [
    ("byte",   lambda s: bytes([s]),          range(0, 256)),
    ("u16be",  lambda s: s.to_bytes(2, "big"),    range(0, 4096)),
    ("u16le",  lambda s: s.to_bytes(2, "little"), range(0, 4096)),
    ("u256be", lambda s: s.to_bytes(32, "big"),   range(0, 4096)),
    ("ascii",  lambda s: str(s).encode(),     range(0, 256)),
]
ENCS_SMALL = [  # s in {0,1,2} under every encoding (calibration selectors)
    ("byte",   lambda s: bytes([s])),
    ("u16be",  lambda s: s.to_bytes(2, "big")),
    ("u16le",  lambda s: s.to_bytes(2, "little")),
    ("u256be", lambda s: s.to_bytes(32, "big")),
    ("ascii",  lambda s: str(s).encode()),
]

t0 = time.time()

# ---- Phase 0: calibration — original SHA-256 scheme must reproduce the OLD triple
cal = {name: h_sha(messerene(PATTERN, SEL + bytes([s])))
       for name, s in (("P", 1), ("Q", 2), ("R", 0))}
RESULTS["calibration_ok"] = (cal == OLD)
assert cal == OLD, f"CALIBRATION FAILED: {cal} != {OLD}"
print("Phase 0 CALIBRATION: old triple reproduced exactly under original SHA-256 scheme", flush=True)
begin("0_calibration_original_sha256", "original messerene() + sha256 h at s in {1,2,0}; gate for all negatives below")
for name, s in (("P", 1), ("Q", 2), ("R", 0)):
    check(f"calibration k=messerene(PATTERN, SEL||byte({s})), h=sha256(k)[:8] (= old h{name.lower()}, not a v3 target)",
          h_sha(messerene(PATTERN, SEL + bytes([s]))))
end()

# ---- Family 1a: direct keccak, formula as specified:
#      k_s = (keccak256(PRE || P_bytes || SEL || enc(s)) mod (n-1)) + 1 ; h = keccak256(k)[:8]
begin("1a_keccak_selector_pregenesis_formula",
      "k=(keccak256(b'MESSERENE/PREGENESIS/v1'||P_bytes||b'MESSERENE/SEL='||enc(s)) mod (n-1))+1, h=keccak256(k 32B BE)[:8]; enc: byte 0..255, u16be/u16le/u256be 0..4095, ascii 0..255")
for enc_name, enc_fn, rng in ENCS_FULL:
    for s in rng:
        k = k_1a(enc_fn(s))
        check(f"k=(keccak256(PRE||P_bytes||SEL||{enc_name}({s})) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
    print(f"    1a {enc_name} done", flush=True)
end()

# ---- Family 1b: structural mirror — messerene() with keccak swapped for sha256:
#      k_s = (keccak256(SEL || enc(s) || P_bytes) mod (n-1)) + 1 ; h = keccak256(k)[:8]
begin("1b_keccak_selector_structural_mirror",
      "k=(keccak256(b'MESSERENE/SEL='||enc(s)||P_bytes) mod (n-1))+1, h=keccak256(k 32B BE)[:8]; same encodings/ranges as 1a")
for enc_name, enc_fn, rng in ENCS_FULL:
    for s in rng:
        k = k_1b(enc_fn(s))
        check(f"k=(keccak256(SEL||{enc_name}({s})||P_bytes) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
    print(f"    1b {enc_name} done", flush=True)
end()

# ---- Family 2: mixed — k from the ORIGINAL sha256 derive, h = keccak256(k)[:8]
begin("2_mixed_sha256_k_keccak_h",
      "k=(sha256(SEL||enc(s)||P_bytes) mod (n-1))+1 (original derive), h=keccak256(k 32B BE)[:8]; same encodings/ranges as 1a")
for enc_name, enc_fn, rng in ENCS_FULL:
    for s in rng:
        k = k_sha(enc_fn(s))
        check(f"k=(sha256(SEL||{enc_name}({s})||P_bytes) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
    print(f"    2 {enc_name} done", flush=True)
end()

# ---- Family 3: mixed — k keccak-derived (1a and 1b), h = sha256(k)[:8]
begin("3_mixed_keccak_k_sha256_h",
      "k as in 1a/1b, h=sha256(k 32B BE)[:8]; enc: byte 0..255, u16be/u16le 0..4095, u256be/ascii 0..255")
ENCS_F3 = [
    ("byte",   lambda s: bytes([s]),          range(0, 256)),
    ("u16be",  lambda s: s.to_bytes(2, "big"),    range(0, 4096)),
    ("u16le",  lambda s: s.to_bytes(2, "little"), range(0, 4096)),
    ("u256be", lambda s: s.to_bytes(32, "big"),   range(0, 256)),
    ("ascii",  lambda s: str(s).encode(),     range(0, 256)),
]
for scheme, kfn, sdesc in (("1a", k_1a, "keccak256(PRE||P_bytes||SEL||enc)"),
                           ("1b", k_1b, "keccak256(SEL||enc||P_bytes)")):
    for enc_name, enc_fn, rng in ENCS_F3:
        for s in rng:
            k = kfn(enc_fn(s))
            check(f"k=({sdesc} with enc={enc_name}({s})) mod (n-1))+1 [{scheme}]; h=sha256(k)[:8]", h_sha(k))
        print(f"    3/{scheme} {enc_name} done", flush=True)
end()

# ---- Family 4: Ethereum-address forms.
#      For candidate k (families 1-3 schemes at s in {0,1,2} under every encoding,
#      plus both main derives), address = keccak256(x||y)[-20:]; candidates =
#      first 8 bytes of: address bytes, keccak256(address), keccak256 of the
#      address hex ASCII (lowercase and EIP-55 checksummed, with/without 0x).
def eth_address(k):
    x, y = mul(k)
    return keccak256(x.to_bytes(32, "big") + y.to_bytes(32, "big"))[-20:]

def eip55(addr_bytes):
    hx = addr_bytes.hex()
    kh = keccak256(hx.encode()).hex()
    return "".join(c.upper() if c in "abcdef" and int(kh[i], 16) >= 8 else c
                   for i, c in enumerate(hx))

# address-derivation ground truth: k=1 -> 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf
assert eth_address(1).hex() == "7e5f4552091a69125d5dfcb7b8c2659029395bdf", "ADDRESS VECTOR FAILED"
print("    address-derivation vector (k=1) verified", flush=True)

begin("4_ethereum_address_forms",
      "k from schemes {sha256-orig, keccak-1a, keccak-1b} x encodings {byte,u16be,u16le,u256be,ascii} x s in {0,1,2}, plus main derives (sha256 and keccak PREGENESIS); addr=keccak256(x||y)[-20:]; h candidates = [:8] of addr bytes, keccak256(addr), keccak256(hex ascii) lower/EIP-55 with/without 0x")
cands = []
for scheme, kfn in (("sha256-orig", k_sha), ("keccak-1a", k_1a), ("keccak-1b", k_1b)):
    for enc_name, enc_fn in ENCS_SMALL:
        for s in (0, 1, 2):
            cands.append((f"{scheme} k via enc={enc_name}({s})", kfn(enc_fn(s))))
cands.append(("main-derive sha256 k=derive(PATTERN)", derive(PATTERN)[0]))
cands.append(("main-derive keccak k=(keccak256(PRE||P_bytes) mod (n-1))+1", wrap(keccak256(PRE + PB))))
for label, k in cands:
    addr = eth_address(k)
    hx, cs = addr.hex(), eip55(addr)
    check(f"{label}; addr[:8] (addr=keccak256(pub64)[-20:])", addr[:8].hex())
    check(f"{label}; keccak256(addr bytes)[:8]", keccak256(addr)[:8].hex())
    check(f"{label}; keccak256('0x'+addr.hex())[:8]", keccak256(("0x" + hx).encode())[:8].hex())
    check(f"{label}; keccak256(addr.hex())[:8]", keccak256(hx.encode())[:8].hex())
    check(f"{label}; keccak256('0x'+eip55(addr))[:8]", keccak256(("0x" + cs).encode())[:8].hex())
    check(f"{label}; keccak256(eip55(addr))[:8]", keccak256(cs.encode())[:8].hex())
end()

# ---- Family 5: pattern-form variants + ETH domain substitutions (families 1-2, s in {0,1,2})
#      and n=0x7c2bac1d placements mirroring v3_sweep.py Phase 5 (byte selectors 0..255).
begin("5_pattern_domain_variants_and_n_placements",
      "pattern material in {P_bytes, PATTERN ascii upper, ascii lower, keccak256(P_bytes)}; domains in {PREGENESIS/v1, MESSERENE/ETHEREUM/v1, MESSERENE/PREGENESIS/ETH/v1}; s in {0,1,2} (byte + u256be encodings); plus n placements at byte selectors 0..255")
PMATS = [("P_bytes", PB), ("ascii-upper", PATTERN.encode()),
         ("ascii-lower", PATTERN.lower().encode()), ("keccak256(P_bytes)", keccak256(PB))]
DOMS = [("PREGENESIS/v1", PRE), ("ETHEREUM/v1", b"MESSERENE/ETHEREUM/v1"),
        ("PREGENESIS/ETH/v1", b"MESSERENE/PREGENESIS/ETH/v1")]
for dname, dom in DOMS:
    for pname, pmat in PMATS:
        for enc_name, enc_fn in (("byte", lambda s: bytes([s])),
                                 ("u256be", lambda s: s.to_bytes(32, "big"))):
            for s in (0, 1, 2):
                k = wrap(keccak256(dom + pmat + SEL + enc_fn(s)))
                check(f"k=(keccak256({dname}||{pname}||SEL||{enc_name}({s})) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
        # main-derive style (no selector) under the same domain/pattern pair
        k = wrap(keccak256(dom + pmat))
        check(f"k=(keccak256({dname}||{pname}) mod (n-1))+1 [main-derive style]; h=keccak256(k)[:8]", h_kec(k))
        check(f"k=(keccak256({dname}||{pname}) mod (n-1))+1 [main-derive style]; h=sha256(k)[:8]", h_sha(k))
for pname, pmat in PMATS:  # family-2 style (sha k) and 1b style with pattern material swapped
    for enc_name, enc_fn in ENCS_SMALL:
        for s in (0, 1, 2):
            k = k_sha(enc_fn(s), pmat)
            check(f"k=(sha256(SEL||{enc_name}({s})||{pname}) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
            k = k_1b(enc_fn(s), pmat)
            check(f"k=(keccak256(SEL||{enc_name}({s})||{pname}) mod (n-1))+1; h=keccak256(k)[:8]", h_kec(k))
# n placements in the selector domain (keccak schemes, byte selectors 0..255)
for s in range(256):
    b = bytes([s])
    for tag, k in (
        ("1b SEL||byte||nBE", wrap(keccak256(SEL + b + NB_BE + PB))),
        ("1b SEL||byte||nLE", wrap(keccak256(SEL + b + NB_LE + PB))),
        ("1b nBE||SEL||byte", wrap(keccak256(NB_BE + SEL + b + PB))),
        ("1a PRE||P||SEL||byte||nBE", wrap(keccak256(PRE + PB + SEL + b + NB_BE))),
        ("1a PRE||P||SEL||byte||nLE", wrap(keccak256(PRE + PB + SEL + b + NB_LE))),
        ("1a nBE||PRE||P||SEL||byte", wrap(keccak256(NB_BE + PRE + PB + SEL + b))),
    ):
        check(f"n-placement {tag} sel={s}; k as tagged; h=keccak256(k)[:8]", h_kec(k))
# n placements inside the h hash (keccak forms; k from sha-orig and keccak-1b)
for s in range(256):
    for klabel, k in (("sha-orig", k_sha(bytes([s]))), ("keccak-1b", k_1b(bytes([s])))):
        kb = k.to_bytes(32, "big")
        check(f"h=keccak256(k||nBE)[:8], k={klabel} sel={s}", keccak256(kb + NB_BE)[:8].hex())
        check(f"h=keccak256(nBE||k)[:8], k={klabel} sel={s}", keccak256(NB_BE + kb)[:8].hex())
        check(f"h=keccak256((k^n) 32B BE)[:8], k={klabel} sel={s}",
              keccak256((k ^ NV3).to_bytes(32, "big"))[:8].hex())
        check(f"h=sha256(k||nBE)[:8], k={klabel} sel={s}", hashlib.sha256(kb + NB_BE).hexdigest()[:16])
        check(f"h=sha256(nBE||k)[:8], k={klabel} sel={s}", hashlib.sha256(NB_BE + kb).hexdigest()[:16])
end()

# ---- Family 6: direct keccak dictionary (keccak mirror of v3_sweep.py Phase 6)
begin("6_keccak_dictionary",
      "keccak256(w)[:8] and keccak256(keccak256(w))[:8] over the original Phase-6 word list")
words = [PATTERN.encode(), PB, b"v3", b"V3", b"MESSERENE", b"AETHER",
         b"760515aafaed2fdc", NB_BE, NB_LE, PATTERN.lower().encode(),
         b"MESSERENE/PREGENESIS/v3", b"AETHER/v3",
         b"Hhp=760515aafaed2fdc|hq=9d9097b3edf2f947|hr=f2d890b337fb40d5|n=0x7c2bac1d"]
for w in words:
    check(f"keccak256({w[:24]!r})[:8]", keccak256(w)[:8].hex())
    check(f"keccak256(keccak256({w[:24]!r}))[:8]", keccak256(keccak256(w))[:8].hex())
end()

all_hits = [h for f in RESULTS["families"].values() for h in f["hits"]]
print(f"\nTOTAL tried: {RESULTS['total_tried']}   TOTAL component hits: {len(all_hits)}   "
      f"calibration_ok: {RESULTS['calibration_ok']}   elapsed: {time.time() - t0:.0f}s")
for h in all_hits:
    print(" ", h)
print("ALL THREE COMPONENTS HIT — candidate solve, requires independent re-run"
      if len({x['component'] for x in all_hits}) == 3 else "triple not solved in this space")
