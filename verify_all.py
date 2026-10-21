#!/usr/bin/env python3
"""
verify_all.py — THE AETHER PROOF, verified end to end.

Python standard library + the bundled lib/ modules ONLY.
No network, no workspace imports. Run:  python3 verify_all.py
Exit code is nonzero if any check fails.
"""
import hashlib, json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "lib"))
import secp256k1 as secp
import genesis_fork as gf
from keccak import keccak256

DATA = os.path.join(HERE, "data")
OPERATOR_PUB = bytes.fromhex(
    "03507f779ca71b6a54fbb2506ce02f898a9a950094714788828d804f5bb2d52e12")
CAPSULE_SHA256 = "d0173ec2234e78eab2dbee62b74e126cb9b4f0d53034e0c694d380d2bcf8c4b1"
STMT_SHA256 = "68c21abe925f9329ca38b49cee492dee5e44221e19e92193ac3467809ecef2fa"
N = secp.N

failures = 0

def check(name, ok, detail=""):
    global failures
    print(("PASS" if ok else "FAIL"), "-", name, ("| " + detail if detail else ""))
    if not ok:
        failures += 1

def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True).encode()

def lzb(b32):
    v = int.from_bytes(b32, "big")
    return 256 - v.bit_length() if v else 256

# ======================================================================
print("== (a) Aether sealed chain (data/aether_chain.jsonl) ==")
W = [0x9E379, 0x85EB1, 0xC2B2B, 0x27D4D, 0x1656D, 0xD3A61, 0x7FEB3]

def rotl(x, r):
    return ((x << r) | (x >> (32 - r))) & 0xFFFFFFFF

def predictor(T0):
    D = gf.sha256d(T0)
    lanes = struct.unpack(">7I", D[:28])
    return sum(rotl(lanes[f], (7 * (f + 1)) % 32) * W[f]
               for f in range(7)) & 0xFFFFFFFF

recs = [json.loads(l) for l in open(os.path.join(DATA, "aether_chain.jsonl"))]
check("aether: record count == 14", len(recs) == 14, f"got {len(recs)}")
prev_disp = None
for rec in recs:
    h = rec["height"]
    cb = bytes.fromhex(rec["txs"][0])
    pi = bytes.fromhex(rec["prev"])
    merkle_b = bytes.fromhex(rec["merkle"])
    merkle_ok = gf.merkle_root([gf.txid(cb)]) == merkle_b
    T0 = gf.ser_header(rec["version"], pi, merkle_b, rec["time"], rec["bits"], 0)
    nonce_ok = predictor(T0) == rec["nonce"]
    hdr = gf.ser_header(rec["version"], pi, merkle_b, rec["time"],
                        rec["bits"], rec["nonce"])
    digest = gf.sha256d(hdr)
    hash_ok = digest[::-1].hex() == rec["hash"]
    link_ok = (prev_disp is None and pi == bytes(32)) or \
              (prev_disp is not None and pi[::-1].hex() == prev_disp)
    sl = rec["seal"]
    pt = secp.decompress(bytes.fromhex(sl["pubkey_compressed"]))
    seal_ok = secp._verify_rs(pt, digest, int(sl["r"], 16), int(sl["s"], 16))
    pub_ok = sl["pubkey_compressed"] == OPERATOR_PUB.hex()
    ok = merkle_ok and nonce_ok and hash_ok and link_ok and seal_ok and pub_ok
    check(f"aether block {h}: merkle/nonce/hash/link/seal/operator-pubkey",
          ok, f"merkle={merkle_ok} nonce={nonce_ok} hash={hash_ok} "
              f"link={link_ok} seal={seal_ok} pub={pub_ok}")
    prev_disp = rec["hash"]

# ======================================================================
print("== (b) The capsule (data/capsule.json) ==")
capsule = json.load(open(os.path.join(DATA, "capsule.json")))
core = {k: capsule[k] for k in ("type", "version", "created_unix", "work",
                                "pattern", "merge", "identity", "btc_height")}
digest = hashlib.sha256(canon(core)).digest()
check("capsule: seal digest == sha256(canonical core)",
      digest.hex() == capsule["seal"]["digest_sha256"], digest.hex())
check("capsule: operator ECDSA seal verifies",
      secp.verify(bytes.fromhex(capsule["seal"]["signer_pubkey_compressed"]),
                  bytes.fromhex(capsule["seal"]["signature_hex"]), digest))
rest = {k: v for k, v in capsule.items() if k != "capsule_sha256"}
recomputed = hashlib.sha256(canon(rest)).hexdigest()
check("capsule: capsule_sha256 recomputed == recorded == d0173ec2...",
      recomputed == capsule["capsule_sha256"] == CAPSULE_SHA256, recomputed)

# ======================================================================
print("== (c) The work record (data/jackpot_certificate.json) ==")
cert = json.load(open(os.path.join(DATA, "jackpot_certificate.json")))
hl = cert["headline"]
import re
m = re.search(r"Header \(hex\): ([0-9a-f]{160})", cert["statement"])
embedded = bytes.fromhex(m.group(1))
rebuilt = gf.ser_header(1, bytes.fromhex(cert["tip_hash"])[::-1],
                        bytes.fromhex(cert["coinbase_txid"])[::-1],
                        cert["header_time"], int(cert["bits"], 16), hl["nonce"])
check("work: header rebuilt from certificate fields == embedded header",
      rebuilt == embedded)
dg = gf.sha256d(embedded)
check("work: sha256d(rebuilt header) == recorded headline hash",
      dg[::-1].hex() == hl["hash"], dg[::-1].hex())
check("work: exactly 32 leading zero bits (display order)",
      lzb(dg[::-1]) == 32 == hl["lzb"], f"lzb={lzb(dg[::-1])}")
check("work: certificate itself states it does NOT meet the network target",
      cert["meets_network_target"] is False)

# ======================================================================
print("== (d) The pattern statement (data/statement_genesis.txt) ==")
stmt = open(os.path.join(DATA, "statement_genesis.txt"), "rb").read()
check("pattern: sha256(statement) == 68c21abe... == capsule pattern field",
      hashlib.sha256(stmt).hexdigest() == STMT_SHA256 ==
      capsule["pattern"]["genesis_challenge_statement_sha256"])

# ======================================================================
print("== (e) Fork anchors (data/fork_records.json + capsule) ==")
fork = json.load(open(os.path.join(DATA, "fork_records.json")))
r68, r74 = fork["fork_height_23668"], fork["fork_height_23674"]
cb74 = bytes.fromhex(r74["txs"][0])
needle = ("AETHERPROOF " + CAPSULE_SHA256).encode()
check("fork: block 23674 coinbase contains the capsule anchor text",
      needle in cb74, f"height={r74['height']} hash={r74['hash'][:16]}...")
mg = capsule["merge"]
child_hdr = bytes.fromhex(mg["child_header_hex"])
cdg = gf.sha256d(child_hdr)
check("fork: capsule child header hashes to capsule child hash (internal)",
      cdg.hex() == mg["child_hash_internal"])
check("fork: capsule child hash (display) matches",
      cdg[::-1].hex() == mg["child_hash_display"])
check("fork: capsule child prev == fork block 23668 hash",
      child_hdr[4:36][::-1].hex() == r68["hash"], r68["hash"][:16] + "...")
check("fork: capsule child merkle == txid(capsule child coinbase) [bonus]",
      gf.txid(bytes.fromhex(mg["coinbase_hex"])) == child_hdr[36:68])

# ======================================================================
print("== (f) Cross-signed attestation (data/aether_attestation.*) ==")
att_txt = open(os.path.join(DATA, "aether_attestation.txt"), "rb").read()
att = json.load(open(os.path.join(DATA, "aether_attestation.json")))
text = att_txt.decode()
marker = "\nbtc_operator_sig_sha256(body): "
body, sig_in_text = text.rsplit(marker, 1)
sig_in_text = sig_in_text.strip()
check("attestation: BTC sig in text == attestation.json btc_operator_sig",
      sig_in_text == att["btc_operator_sig"])
h = hashlib.sha256(body.encode()).digest()
r = int(sig_in_text[:64], 16); s = int(sig_in_text[64:], 16)
pt = secp.decompress(OPERATOR_PUB)
check("attestation: BTC operator signature verifies over sha256(body)",
      secp._verify_rs(pt, h, r, s))
raw = bytes.fromhex(att["eth_signature"][2:])
er, es, ev = (int.from_bytes(raw[:32], "big"),
              int.from_bytes(raw[32:64], "big"), raw[64])
edigest = keccak256(b"\x19Ethereum Signed Message:\n" +
                    str(len(att_txt)).encode() + att_txt)
z = int.from_bytes(edigest, "big")
recid = ev - 27
R = secp.decompress(bytes([0x02 | (recid & 1)]) + er.to_bytes(32, "big"))
Q = secp._mul(pow(er, -1, N),
              secp._add(secp._mul(es, R), secp._mul((-z) % N)))
recovered = "0x" + keccak256(Q[0].to_bytes(32, "big") +
                              Q[1].to_bytes(32, "big"))[-20:].hex()
check("attestation: ETH signature recovers to 0x24E8384B...D8B9",
      recovered.lower() == att["eth_address"].lower() ==
      "0x24e8384b007e5f72bd72e479006c9a3a95b9d8b9", recovered)

# ======================================================================
print("== (g) Challenge calibration (lib/messerene_operator.py) ==")
import messerene_operator as mo
cal = {}
for name, s in (("P", 1), ("Q", 2), ("R", 0)):
    ks = mo.messerene(mo.PATTERN, b"MESSERENE/SEL=" + bytes([s]))
    cal[name] = hashlib.sha256(ks.to_bytes(32, "big")).hexdigest()[:16]
check("challenge: calibration triple reproduced from the public pattern",
      cal == {"P": "5f655bd61a946c54", "Q": "a491c2683b267ab3",
              "R": "8dfe290f8dc993f5"},
      f"hp={cal['P']} hq={cal['Q']} hr={cal['R']}")

# ======================================================================
print()
if failures:
    print(f"VERDICT: {failures} CHECK(S) FAILED")
    sys.exit(1)
print("VERDICT: ALL CHECKS PASS")
