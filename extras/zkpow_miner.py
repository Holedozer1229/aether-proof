#!/usr/bin/env python3
"""
zkpow_miner.py — SHA256d ZK-PoW miner (the honest form of "zk mined").

CONSTRUCTION
------------
1. MINING: grind sha256d over real 80-byte Bitcoin-style headers at a
   configurable target (default 2^248). For EVERY candidate nonce n,
   the block's coinbase commits W = n*G (secp256k1) in its scriptSig,
   so the header's merkle root — and therefore the block hash — binds
   W before the hash is ever taken. (W is advanced by one point
   addition per candidate: W_{n+1} = W_n + G, exactly n*G.)
2. ZK PACKAGE: { block_hash, target, W, timestamp, Schnorr
   signature-of-knowledge (Fiat-Shamir) under private key = nonce
   over msg = block_hash || timestamp }. A verifier checks
   block_hash < target and the SoK against W, and may conclude
   exactly this: "the prover knows the discrete log of W, and W is
   committed inside a block whose hash meets the target" — proof of
   KNOWLEDGE of a winning nonce, revealing neither header nor nonce.
3. REVEAL: open the full header + coinbase; a second verifier checks
   the header hashes to block_hash, the header nonce's point equals
   W, the merkle root recomputes from the coinbase (which contains
   W), and PoW meets target. This revealed header is the only part
   any consensus could ever consume.

SCOPE — READ BEFORE CITING THIS FILE
------------------------------------
* Bitcoin consensus does NOT consume ZK proofs. It consumes the
  revealed header and checks one hash comparison. This ZK layer
  provides PRE-BROADCAST proof of possession / priority
  (anti-front-running, timestamped claim of "I found it first")
  and nothing more. The proof does NOT make any block
  consensus-valid by itself; only a revealed header meeting the
  network target does that, and this demo grinds a configurable
  target (default 2^248), NOT the ~2^79-bit network target.
* Secrecy bound: a mining nonce is 32 bits, so W = nonce*G alone
  permits brute-force recovery of the nonce in at most 2^32 point
  additions. The SoK is a genuine zero-knowledge proof of knowledge
  as a protocol, but the nonce's practical secrecy is bounded by
  the 32-bit nonce space. Treat the package as a priority claim,
  not a vault.

Reuses the workspace's own helpers: secp256k1.py (curve),
genesis_fork.py (sha256d / header / merkle), txscript.py (tx ser).
Stdlib otherwise. No mocked proofs: every check below is real
cryptography executed in the run.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import time

sys.path.insert(0, os.path.expanduser("~/workspace"))
import secp256k1 as secp          # P, N, G, _add, _mul, compress, decompress
import genesis_fork as gf         # sha256d, txid, ser_header, merkle_root, push, target_to_bits
import txscript                   # ser_tx, lock_open

N = secp.N
G = secp.G

# ---------------------------------------------------------------- miner

def build_coinbase(height: int, W_point) -> bytes:
    """Coinbase whose scriptSig commits W = nonce*G (the binding)."""
    script = (gf.push(height.to_bytes(3, "little"))
              + gf.push(b"ZKPOW-MINER")
              + gf.push(secp.compress(W_point)))
    tx = {"version": 1,
          "vin": [{"prev": b"\x00" * 32, "idx": 0xFFFFFFFF,
                   "script": script, "seq": 0xFFFFFFFF}],
          "vout": [{"value": 312500000, "script": txscript.lock_open()}],
          "locktime": 0}
    return txscript.ser_tx(tx)


def mine(target: int, height: int = 840000, max_tries: int = 0):
    """Grind nonces 1,2,3,...; W tracks nonce*G by point addition.
    Returns (header_bytes, coinbase_bytes, nonce, block_hash_internal)."""
    bits = gf.target_to_bits(target)
    t0 = int(time.time())
    prev = b"\x00" * 32
    W = None                     # 0*G = infinity; nonce starts at 1
    nonce = 0
    tries = 0
    while True:
        nonce += 1
        W = secp._add(W, G)      # now W = nonce*G exactly
        cb = build_coinbase(height, W)
        merkle = gf.merkle_root([gf.txid(cb)])
        hdr = gf.ser_header(1, prev, merkle, t0, bits, nonce)
        h = gf.sha256d(hdr)
        tries += 1
        if int.from_bytes(h, "little") < target:
            return hdr, cb, nonce, h
        if max_tries and tries >= max_tries:
            return None


# ------------------------------------------------- Schnorr SoK (Fiat-Shamir)

def _msg(block_hash_internal: bytes, timestamp: int) -> bytes:
    return b"ZKPOW-SOK/v1" + block_hash_internal + timestamp.to_bytes(8, "big")


def sok_sign(x: int, W_point, block_hash_internal: bytes, timestamp: int):
    """Signature of knowledge of x = dlog(W) over msg. Deterministic k."""
    msg = _msg(block_hash_internal, timestamp)
    xb = x.to_bytes(32, "big")
    ctr = 0
    while True:
        k = int.from_bytes(hashlib.sha256(
            b"ZKPOW-K/v1" + bytes([ctr]) + xb + msg).digest(), "big") % N
        if k:
            break
        ctr += 1
    R = secp._mul(k)
    e = int.from_bytes(hashlib.sha256(
        b"ZKPOW-E/v1" + secp.compress(R) + secp.compress(W_point) + msg
    ).digest(), "big") % N
    s = (k + e * x) % N
    return {"R": secp.compress(R).hex(), "s": "%064x" % s}


def sok_verify(W_point, sok: dict, block_hash_internal: bytes,
               timestamp: int) -> bool:
    """Check s*G == R + e*W with e recomputed Fiat-Shamir style."""
    try:
        R = secp.decompress(bytes.fromhex(sok["R"]))
        s = int(sok["s"], 16)
    except Exception:
        return False
    if not (1 <= s < N):
        return False
    msg = _msg(block_hash_internal, timestamp)
    e = int.from_bytes(hashlib.sha256(
        b"ZKPOW-E/v1" + secp.compress(R) + secp.compress(W_point) + msg
    ).digest(), "big") % N
    return secp._mul(s) == secp._add(R, secp._mul(e, W_point))


# ---------------------------------------------------------------- package

def make_package(block_hash_internal: bytes, target: int, nonce: int,
                 W_point, timestamp: int) -> dict:
    return {
        "block_hash": block_hash_internal[::-1].hex(),   # display order
        "target": "%064x" % target,
        "W": secp.compress(W_point).hex(),
        "timestamp": timestamp,
        "sok": sok_sign(nonce, W_point, block_hash_internal, timestamp),
    }


def zk_verify(pkg: dict) -> bool:
    """ZK-phase verifier: sees NO header and NO nonce. Checks only
    block_hash < target and the SoK against W."""
    try:
        bh_internal = bytes.fromhex(pkg["block_hash"])[::-1]
        target = int(pkg["target"], 16)
        W = secp.decompress(bytes.fromhex(pkg["W"]))
        ts = int(pkg["timestamp"])
    except Exception:
        return False
    if not (int.from_bytes(bh_internal, "little") < target):
        return False
    return sok_verify(W, pkg["sok"], bh_internal, ts)


def reveal_verify(header: bytes, coinbase: bytes, pkg: dict) -> bool:
    """Reveal-phase verifier: the consensus-shaped checks. Header must
    hash to the package's block_hash, meet target, its nonce's point
    must equal W, and its merkle root must recompute from a coinbase
    that actually contains W."""
    try:
        target = int(pkg["target"], 16)
        W = secp.decompress(bytes.fromhex(pkg["W"]))
    except Exception:
        return False
    if len(header) != 80:
        return False
    h = gf.sha256d(header)
    if h[::-1].hex() != pkg["block_hash"]:
        return False
    if not (int.from_bytes(h, "little") < target):
        return False
    nonce = struct.unpack("<I", header[76:80])[0]
    if secp.compress(secp._mul(nonce)).hex() != pkg["W"]:
        return False
    merkle = gf.merkle_root([gf.txid(coinbase)])
    if header[36:68] != merkle:
        return False
    if secp.compress(W) not in coinbase:
        return False
    return True


# ------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description="SHA256d ZK-PoW miner")
    ap.add_argument("--target-exp", type=int, default=248,
                    help="target = 2**EXP (default 248: a find in seconds)")
    ap.add_argument("--max-tries", type=int, default=0,
                    help="0 = grind until found")
    args = ap.parse_args()
    target = 1 << args.target_exp

    print("=" * 70)
    print("SHA256d ZK-PoW MINER — mine, prove knowledge, reveal")
    print("=" * 70)
    print(f"target            : 2^{args.target_exp} "
          f"(expected ~2^{256 - args.target_exp} tries)")

    t_start = time.time()
    found = mine(target, max_tries=args.max_tries)
    if found is None:
        print("no find within --max-tries; aborting")
        return 1
    header, coinbase, nonce, bh = found
    elapsed = time.time() - t_start
    W = secp._mul(nonce)
    # cross-check the incremental grind: _mul(nonce) == point in coinbase
    assert secp.compress(W) in coinbase, "W binding broken"
    ts = int(time.time())
    pkg = make_package(bh, target, nonce, W, ts)

    print(f"FOUND after grind : {elapsed:.2f}s")
    print(f"block_hash        : {bh[::-1].hex()}")
    print(f"target            : {'%064x' % target}")
    print(f"winning nonce     : {nonce}  (kept secret in the ZK phase)")
    print(f"W = nonce*G       : {pkg['W']}")
    print(f"package timestamp : {ts}")
    print(f"SoK R             : {pkg['sok']['R']}")
    print(f"SoK s             : {pkg['sok']['s']}")

    pkg_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "zkpow_last_package.json")
    with open(pkg_path, "w") as f:
        json.dump(pkg, f, indent=2)
    print(f"package written   : {pkg_path}")

    print("-" * 70)
    print("SELF-TESTS (real cryptography, executed now)")
    results = {}

    def check(name, ok):
        results[name] = bool(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")

    # 1. honest package verifies in the ZK phase
    check("honest ZK package verifies (hash<target + SoK vs W)",
          zk_verify(pkg))

    # 2. forged SoK: attacker signs the same msg with a WRONG key but
    #    aims the challenge at the claimed W -> must be rejected
    forged = dict(pkg)
    # attacker computes R from own k, e over the CLAIMED W, s with wrong key
    x_bad = 0xDEADBEEF
    msg = _msg(bh, ts)
    k = int.from_bytes(hashlib.sha256(
        b"ZKPOW-K/v1" + b"\x00" + x_bad.to_bytes(32, "big") + msg
    ).digest(), "big") % N
    R = secp._mul(k)
    e = int.from_bytes(hashlib.sha256(
        b"ZKPOW-E/v1" + secp.compress(R) + secp.compress(W) + msg
    ).digest(), "big") % N
    forged["sok"] = {"R": secp.compress(R).hex(),
                     "s": "%064x" % ((k + e * x_bad) % N)}
    check("forged SoK (wrong private key) REJECTED", not zk_verify(forged))

    # 3. SoK made with nonce+1 as the key -> rejected against W
    off = dict(pkg)
    k2 = int.from_bytes(hashlib.sha256(
        b"ZKPOW-K/v1" + b"\x00" + (nonce + 1).to_bytes(32, "big") + msg
    ).digest(), "big") % N
    R2 = secp._mul(k2)
    e2 = int.from_bytes(hashlib.sha256(
        b"ZKPOW-E/v1" + secp.compress(R2) + secp.compress(W) + msg
    ).digest(), "big") % N
    off["sok"] = {"R": secp.compress(R2).hex(),
                  "s": "%064x" % ((k2 + e2 * (nonce + 1)) % N)}
    check("SoK with nonce+1 as key REJECTED", not zk_verify(off))

    # 4. tampered block_hash (flip lowest bit: stays < target, so the
    #    rejection must come from the SoK itself) -> rejected
    tampered = dict(pkg)
    bh_t = bytearray(bh)
    bh_t[0] ^= 0x01                      # internal byte 0 = low-order byte
    tampered["block_hash"] = bytes(bh_t)[::-1].hex()
    check("tampered block_hash REJECTED", not zk_verify(tampered))

    # 5a. reveal phase passes on the real header + coinbase
    check("reveal verifies on the real header", reveal_verify(header, coinbase, pkg))

    # 5b. reveal fails on a header with a swapped nonce
    bad_header = header[:76] + struct.pack("<I", nonce + 1)
    check("reveal REJECTS header with swapped nonce",
          not reveal_verify(bad_header, coinbase, pkg))

    print("-" * 70)
    n_pass = sum(results.values())
    print(f"self-tests: {n_pass}/{len(results)} passed")
    print()
    print("SCOPE: Bitcoin consensus does not consume ZK proofs — it consumes")
    print("the revealed header and checks sha256d(header) < network target.")
    print("This ZK layer provides pre-broadcast proof of possession/priority")
    print("(anti-front-running, timestamped claim) and nothing more. It does")
    print("not make any block consensus-valid by itself, and this run ground")
    print(f"a 2^{args.target_exp} demo target, not the ~2^79-bit network target.")
    print("Note: W = nonce*G with a 32-bit nonce is brute-forceable in <=2^32")
    print("point additions — the package is a priority claim, not a vault.")
    return 0 if n_pass == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
