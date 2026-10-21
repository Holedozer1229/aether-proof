"""keccak.py — pure-Python Keccak-256 (stdlib only).

Extracted verbatim from the cross-chain attestation builder
(aether_attestation.py), where it was pinned by two test vectors PLUS
a derived-address check against a known Ethereum operator address —
three independent ground truths. The test-vector asserts are kept.
Note: this is original Keccak padding (0x01), as Ethereum uses —
NOT NIST SHA3-256 (0x06).
"""

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A,
       0x8000000080008000, 0x000000000000808B, 0x0000000080000001,
       0x8000000080008081, 0x8000000000008009, 0x000000000000008A,
       0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089,
       0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
       0x000000000000800A, 0x800000008000000A, 0x8000000080008081,
       0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 1, 62, 28, 27], [36, 44, 6, 55, 20], [3, 10, 43, 25, 39],
        [41, 45, 15, 21, 8], [18, 2, 61, 56, 14]]  # [y][x]
_MASK = (1 << 64) - 1

def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _MASK if n else v

def _keccak_f(st):
    for rnd in range(24):
        C = [st[x] ^ st[x + 5] ^ st[x + 10] ^ st[x + 15] ^ st[x + 20] for x in range(5)]
        D = [C[(x - 1) % 5] ^ _rol(C[(x + 1) % 5], 1) for x in range(5)]
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] ^= D[x]
        B = [0] * 25
        for x in range(5):
            for y in range(5):
                B[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(st[x + 5 * y], _ROT[y][x])
        for x in range(5):
            for y in range(5):
                st[x + 5 * y] = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y])
        st[0] ^= _RC[rnd]
    return st

def keccak256(data: bytes) -> bytes:
    rate = 136
    st = [0] * 25
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % rate != rate - 1:
        padded.append(0x00)
    padded.append(0x80)
    for off in range(0, len(padded), rate):
        block = padded[off:off + rate]
        for i in range(rate // 8):
            st[i] ^= int.from_bytes(block[8 * i:8 * i + 8], "little")
        st = _keccak_f(st)
    out = b""
    for i in range(4):
        out += st[i].to_bytes(8, "little")
    return out[:32]

assert keccak256(b"").hex() == "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
assert keccak256(b"abc").hex() == "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
