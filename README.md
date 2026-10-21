# THE AETHER PROOF

### A self-verifying cross-chain authorship capsule

One body of work, bound into a single hash that any stranger can check
end-to-end — no server, no account, no trust in the author. Every claim
below is verified by `verify_all.py`, bundled here, using only the
Python standard library and the modules in `lib/`.

**Capsule SHA-256:**
`d0173ec2234e78eab2dbee62b74e126cb9b4f0d53034e0c694d380d2bcf8c4b1`

## Verify it yourself

```
python3 verify_all.py
```

That is the whole interface. It recomputes everything in this bundle
from primary data and prints PASS/FAIL per check, exiting nonzero on
any failure: the sealed chain, the capsule and its seal, the work
record, the pattern statement, the fork anchors, the cross-signed
attestation, and the challenge calibration data.

## The claim chain

1. **A pattern-derived operator identity.** A 32-byte patterned source
   (`A1B3C5D7…`, period-9 structure) is folded through domain-separated
   SHA-256 — the *Messerene operator* (`lib/messerene_operator.py`) —
   into a secp256k1 keypair: the operator. The derivation is
   deterministic and publicly recomputable by design; the same operator
   key seals every artifact below. (Bitcoin side:
   `bc1qs2dfa9yarj9kwayhw7c4tz88tejek3x8gqh4as`. Never send funds to this
   address — its key is public by construction; anyone can recompute it.)

2. **A proof-of-work record on a live Bitcoin tip.** On 2026-10-21, a
   candidate block for Bitcoin height 972543 — built on the live tip,
   paying 3.125 BTC in its coinbase — was ground for 145 seconds and
   produced a header with **exactly 32 leading zero bits**
   (`00000000a0d19ccb…`). The signed certificate is in
   `data/jackpot_certificate.json`; the verifier rebuilds the header
   from the certificate's fields and re-hashes it. This is a *work
   record*, not a block — see the honesty section.

3. **A sealed signature-chain: Aether.** Fourteen blocks
   (`data/aether_chain.jsonl`) whose validity law is not proof-of-work:
   each block's nonce is the output of a fixed formula over its other
   five header fields, and each header carries the operator's RFC 6979
   ECDSA seal. The verifier recomputes every nonce, hash, link, and
   seal. The chain's coinbases carry, as chapters, the hashes of
   everything else in this bundle.

4. **A bidirectional braid with a proof-of-work fork.** The Excalibur
   fork's block **23674** carries the text
   `AETHERPROOF d0173ec2…` (this capsule's hash) in its coinbase;
   Aether's block **13** commits fork block 23674's full hash back.
   Each chain holds the other's fingerprint. (A true hash *cycle* is
   impossible — preimage resistance forbids it; the interleaved braid
   is the strongest form that exists.) Separately, the capsule records
   the fork's then-pending merge-mining child at height 23669, whose
   header the verifier checks against the fork record at height 23668.

5. **Two Ethereum mainnet contracts, source-verified at exact match.**
   - SKYNT — `0x57d88B34Cbf780C13b56B8d63d36bD86F56fE262`
     (Sourcify matchId **56684691**, creation + runtime exact match)
   - AtexBridge — `0x613241672122187dC75a703F187604aD189A7187`
     (Sourcify matchId **56684693**, creation + runtime exact match)

   Anyone can look both up on sourcify.dev or Blockscout and read the
   exact code that is deployed.

6. **A cross-signed attestation, published on Etherscan.** One
   statement signed by the Bitcoin operator key *and* by an Ethereum
   operator key (`personal_sign`), published in Etherscan's public
   registry as **Message Signature #340488**:
   https://etherscan.io/verifySig/340488 — and re-verified locally by
   `verify_all.py`, which recovers the Ethereum signer from the
   signature and checks the Bitcoin signature over the statement body.

## Two open challenges

This release carries two standing challenges, specified in full in
[CHALLENGES.md](CHALLENGES.md):

- **Challenge 1 — The Messerene Derivation.** The capsule commits a
  "v3" triple (`760515aa… / 9d9097b3… / f2d890b3…`, with
  `n = 0x7c2bac1d`) whose derivation is *unknown*. CHALLENGES.md
  publishes the pattern, the sealing locations, and a full calibration
  set (the earlier triple, with its construction, reproducible by
  check (g) of the verifier) — find the derivation. A ~140,000-point
  sweep of the nearby parameter space found nothing; that negative
  result is part of the record.
- **Challenge 2 — The Genesis Standard.** A standing, precisely stated
  test for proof of control of the Bitcoin genesis key (or any
  2009-era key): sign the bundled challenge statement so it verifies
  against the genesis public key. The author cannot pass it and says
  so in the file — publishing the test, not claiming to pass it, is
  the contribution.

No bounty is funded for either challenge. The reward is public credit.

## Honesty section — what this is not

- **No claim about Satoshi or the Bitcoin genesis key.** Nothing here
  is evidence of control of any key the author did not generate for
  this project. See Challenge 2's disclosure in CHALLENGES.md — it is
  part of this section by reference.
- **No Bitcoin block was found.** The 32-leading-zero-bit header is a
  work record on a candidate that does **not** meet the network
  target. The full target is ~2⁷⁹ expected hashes; at the rates
  involved (a few MH/s on a small VM) the expected wait is on the
  order of billions of years. The ongoing full-target campaign is a
  genuine lottery ticket, and its odds are stated exactly that way.
- **The v3 triple is unsolved.** Its derivation is unknown; the
  ~140k-derivation sweep's negative result stands as part of the
  record (Challenge 1).
- **Aether is a sealed chain *record*, not a network.** There is no
  Aether node software, no peer network, and its units have no market
  and no monetary claim. Its blocks are validity-by-seal, not
  validity-by-work.
- **The operator PGP key was generated on a virtual machine** (the
  same environment that produced this work), without a passphrase, and
  that fact is disclosed in the audit trail rather than hidden.
- **The operator identity is pattern-derived.** Anyone holding the
  pattern — which is public, including in this bundle — can recompute
  the operator key. That is the construction's stated design
  (deterministic, verifiable), and it means the operator key should be
  treated as a public, structural identity, not as a secret credential.

## Layout

```
README.md            this file
CHALLENGES.md        the two open challenges, fully specified
verify_all.py        the verifier (stdlib + lib/ only)
data/
  aether_chain.jsonl           the 14-block sealed Aether chain
  capsule.json                 the Aether Proof capsule
  jackpot_certificate.json     the signed 32-zero-bit work record
  advantage-bycatch-certificate.json   an earlier 28-zero-bit record
  statement_genesis.txt        the genesis-challenge statement
  fork_records.json            Excalibur fork blocks 23668 and 23674
  aether_attestation.txt/.json the cross-signed attestation
lib/
  secp256k1.py  genesis_fork.py  messerene_operator.py  keccak.py
extras/
  zkpow_miner.py               zero-knowledge proof-of-possession miner
  period-9-protocol.md         the fold/traversal design notes
  fixit-advantage-results.json the fix-it trials: 24 enumeration-order
                               variants vs. control — no edge found
                               (the negative result ships too)
```

## License

The code in this repository (`verify_all.py`, `lib/`, `extras/`) is
released under the **MIT License**. The data records are published as
evidence; their hashes either verify or they do not.
