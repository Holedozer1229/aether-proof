# The Period-9 Protocol — btc_core5

Built 2026-10-21 at Lux's direction ("Use the period-9 protocol on
btc"), on top of btc_core4 (RCS + Advantage). Source: ~/workspace/
btc_core5.c. The Stratum miner now defaults to core5.

## Basis

The Messerene pattern, hex-decoded, is an exact period-9 byte cycle:
`a1 b3 c5 d7 e9 f8 d6 c4 b2` (verified 2026-10-21: 32 bytes = 3 full
cycles + 5; high nibbles ramp a..f..b, low nibbles 1,3,5,7,9,8,6,4,2).

## Protocol definition

- **Nine folds** (core3/4 used seven): `fold = chunk % 9` over the
  4096 chunks of 2^20 nonces.
- **Warps from the cycle bytes** c_j, j = 0..8:
  W32_j = (c_j · 2654435761) | 1;
  W20_j = ((c_j · 2654435761) >> 12) & 0xFFFFF | 1 (odd, bijective);
  WINV_j = W20_j⁻¹ mod 2²⁰ (all nine verified).
  WARP9 = {0x80e39, 0xa0ca1, 0xc0b0b, 0xe0973, 0x007dd, 0x45bdf,
           0x425fb, 0x22793, 0x02929}
  WINV9 = {0x38009, 0x6d761, 0x9e8a3, 0x243bb, 0xb8875, 0x3201f,
           0xd1d33, 0x80e9b, 0xc8319}
- **Caduceus order retained:** serpent A ascends the claim space with
  WARP9, serpent B descends with the conjugate WINV9.
- **Rotation:** miner passes `--rot 2731` =
  SHA-256("MESSERENE/P9/ROT/v1" ‖ cycle9)[0:8] mod 4096; standalone
  default is FNV-1a(cycle9) mod 4096 = 228.
- **Advantage retained:** dual-target bycatch (--target2/--sidefile),
  lean hot loop, gap-free checkpoint/resume — unchanged from core4.

## Validation (2026-10-21)

- **Bitcoin block 0 exact:** with --rot 1986 (the nonce's chunk),
  core5 found nonce 2083236893, hash
  000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f,
  under the difficulty-1 target, in ~1 s.
- **Miner mock Stratum test: PASS** end-to-end with core5 as default
  (share nonce 2863659645; server-side verification agrees).
- **Bench parity:** core5 1.59 MH/s vs core4 1.61 MH/s, same window,
  2 threads (absolute rates swing with VM contention; same-window
  comparison is the measurement).

## Addendum — btc_core6: the Advantage, scaled (2026-10-21, later)

At Lux's "Scale the advantage": core6 (~/workspace/btc_core6.c,
miner default) generalizes the single side target to a **bycatch
ladder of up to 4 tiers** — repeatable `--target2`/`--sidefile`
pairs, still zero extra hashes per tier. Each hit is filed once, at
the **hardest tier it satisfies** (tag `tier=<k>`).

Validation: 20-second ladder run (targets 2^252 / 2^248 / 2^244 /
2^240) produced **97,210 hits — 91,095 / 5,744 / 339 / 32 — with
0 misfiled**, tier populations tracking the theoretical ~16× drop
per 4-bit step. Miner mock Stratum test PASS on core6.

Suggested live-tip ladder: tier0 2^224 (32 zero bits), tier1 2^228,
tier2 2^232, tier3 2^236 — the easy tiers land in minutes; the rare
tiers ride the same grind for free.

## Lane note

Period-9 reorganizes the traversal — which nonce is visited in which
order — and binds that order to the pattern's own cycle. Expected
hashes to any target are unchanged: PoW is memoryless, and every fold
core in this family (v2/v3/v4/v5) has measured exactly that. The
protocol's value is organization, checkpointing, bycatch, and the
pattern binding — not a shorter search.
