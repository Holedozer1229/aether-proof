# Two Open Challenges

These challenges are part of the release. Both are stated precisely, both
come with everything needed to check a solution in seconds, and neither
carries a funded bounty — none exists. The reward offered is public credit
in this repository and in the Aether seal record. If you solve one, open an
issue or a pull request with the fully specified derivation; verification
is mechanical.

---

## CHALLENGE 1 — THE MESSERENE DERIVATION

**Find any derivation that produces all three of:**

```
hp = 760515aafaed2fdc
hq = 9d9097b3edf2f947
hr = f2d890b337fb40d5
        with the accompanying parameter  n = 0x7c2bac1d
```

This "v3 triple" is sealed in three places:

- the coinbase of **Excalibur fork block 23606** (as the text
  `Hhp=760515aafaed2fdc|hq=9d9097b3edf2f947|hr=f2d890b337fb40d5|n=0x7c2bac1d`),
- **the Aether Proof capsule**, SHA-256
  `d0173ec2234e78eab2dbee62b74e126cb9b4f0d53034e0c694d380d2bcf8c4b1`
  (see `data/capsule.json`),
- the **payload v2** OP_RETURN design that commits the capsule hash
  alongside the triple's raw bytes (`4145544845522f7632…` — "AETHER/v2"
  ‖ capsule hash ‖ hp‖hq‖hr ‖ n).

Its derivation is **unknown** — including to the author of this
repository. What *is* known is the construction that produced the
earlier ("calibration") triple, published in full so your harness can be
validated on a known answer before you attack the v3 targets.

### The pattern

```
A1B3C5D7E9F8D6C4B2A1B3C5D7E9F8D6C4B2A1B3C5D7E9F8D6C4B2A1B3C5D7E9
```

This is the hex string used by the operator construction in
`lib/messerene_operator.py` (its `PATTERN` constant; the pattern bytes
are `bytes.fromhex(PATTERN)`).

### The calibration set (known answer)

With selectors **P = 1, Q = 2, R = 0**:

```
k_s = messerene(PATTERN, b"MESSERENE/SEL=" + bytes([s]))
      = ( int( SHA-256( b"MESSERENE/SEL=" || byte(s) || P_bytes ) )
          mod (n_curve − 1) ) + 1
h_s = SHA-256( k_s as 32-byte big-endian )[:8]   (hex)
```

the construction yields exactly:

```
hp = 5f655bd61a946c54      (s = 1)
hq = a491c2683b267ab3      (s = 2)
hr = 8dfe290f8dc993f5      (s = 0)
```

`python3 verify_all.py` recomputes this triple as check (g), so the
calibration data in this file is itself verified by the bundle. If your
harness does not reproduce these three values under these parameters,
your harness — not the challenge — needs fixing.

### The negative result (part of the record)

A sweep of roughly **140,000 derivations** across the nearby parameter
space found **zero** of the three v3 components. A second sweep the same
day added **60,943 Ethereum-form derivations** — Keccak-256 mirrors of
every family below, mixed SHA-256/Keccak forms, abi-style `uint256`
selectors, Ethereum-address forms, and `n` placements under both hashes —
and also found **zero** (see `extras/v3_sweep_ethereum.py` and
`extras/v3-sweep-ethereum-results.json`; the harness calibration against
the known triple above passed before either negative was trusted):

- selector bytes 0–255 under the canonical construction;
- 16-bit selectors 0–65535, big-endian and little-endian domain encodings;
- eight domain-string templates (e.g. `MESSERENE/V3/SEL=`,
  `MESSERENE/PREGENESIS/v3`, `AETHER/SEL=`) × selector byte;
- 33 pattern variants (all 31 pair-rotations, the reversed pattern, and
  the pattern as ASCII input instead of hex-decoded bytes) × selector byte;
- the parameter `n = 0x7c2bac1d` in every tried placement: appended to or
  prepended before the domain string (BE/LE), and inside the final hash
  as `sha256(k‖n)`, `sha256(n‖k)`, `sha256(k⊕n)` — × selector byte;
- a direct `sha256`/`sha256d` dictionary over pattern- and
  capsule-related inputs.

So the v3 triple is **not** the Messerene operator construction under any
nearby parameterization. It may use a different scheme entirely, a
different input, or no derivation at all. That is the challenge.

### Rules

A solution is a **fully specified deterministic derivation** — code or an
exact algorithmic description — that:

1. reproduces the calibration triple exactly under its stated parameters
   (proving the scheme is the right family, or honestly framing a new
   one), and
2. yields **all three** v3 components under the same scheme with stated
   parameters, including a stated role for `n = 0x7c2bac1d` (or a proof
   that it plays none).

A single-component match is a coincidence until the other two follow:
each component is 64 bits. Verification takes seconds with
`lib/messerene_operator.py`.

---

## CHALLENGE 2 — THE GENESIS STANDARD

This is the standing test for proof of control of the Bitcoin genesis
key — or of any 2009-era key. It exists so that claims can be checked
instead of debated.

**The test.** Sign the challenge statement in
`data/statement_genesis.txt` (SHA-256
`68c21abe925f9329ca38b49cee492dee5e44221e19e92193ac3467809ecef2fa`)
such that the signature verifies against the Bitcoin genesis public key:

```
04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb6
f447b34d17a3e409243ee15d4e9a424b2cddbe0a0385b92e843f61deb6
```

— or against another 2009-era key accompanied by an independently
checkable claim (for example, a signed message from a key provably
contemporaneous with the early chain). The statement is fixed, carries
its own nonce, and is hash-committed inside the Aether Proof capsule, so
a passing signature cannot be replayed from any other context.

**Disclosure.** The author of this repository **cannot pass this test.**
No signature of this kind has ever been produced in the course of this
work. Nothing in this repository is, or should be read as, evidence of
control of the genesis key or of any key the author did not generate for
this project. Publishing the test — not claiming to pass it — is the
contribution.

If a passing signature ever appears, this file will be updated to say
so, with the signature reproduced in full.
