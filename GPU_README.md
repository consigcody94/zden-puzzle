# GPU Brute Force Guide — Zden Level 5

## Target
- **Address**: `1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7`
- **hash160**: `07e3be6a572ff1b6ba0f8c1c5898edbdf53d1ed5`

## Hypothesis Space

The best-justified hypothesis is **each of 64 rectangles contributes one hex nibble** of the 32-byte private key, where the nibble value comes from the rectangle's horizontal (or vertical) border thickness.

Per-rectangle nibble candidate sets (from `img/sensible.json`):
- **55/64 rectangles** have 1–2 valid nibble candidates (integer thickness solutions of `2·t_h·h + 2·t_v·w − 4·t_h·t_v = shell`).
- **~7 rectangles** (indices 7, 21, 27, 32, 38, 40, 44, 58, 61) have 3–6 candidates.
- **2 rectangles** (39 and 52) have NO integer solution — the author likely altered these (literally the "FIX" rectangle).

### Space sizes

| Variant | Full space | Pruned (top-2 per rect, rects 39/52 free) |
|---|---|---|
| `t_h`-nibble | 1.3 × 10¹² | ~10¹⁰ |
| `t_v`-nibble | 2.0 × 10¹² | ~10¹⁰ |

## Running on GPU

### Option 1 — Use BitCrack (CUDA/OpenCL)
BitCrack searches a *contiguous range* of private keys for a given hash160. Our hypothesis isn't contiguous, but you can:
1. Generate a list of candidate keys (the hypothesis enumeration).
2. Hand them to a GPU kernel that does `privkey → pubkey → sha256 → ripemd160` and compares.

For ~10¹⁰ candidates on an RTX 4090 (≈3 Gkey/s for secp256k1 point multiplication): **~1 hour**.

### Option 2 — Our pre-written brute forcers
- `brute_tight_v2.py` — CPU, multiprocessing + `coincurve`. Runs on 16 cores, ~300K keys/s.
  - Full pruned space for 8 variants ≈ 268M candidates → ~15 min on CPU.
- `brute_force.py` — larger space, also CPU.

### Option 3 — Adapt the iterator to CUDA
The enumeration in `brute_tight_v2.py:iter_combs()` is a simple mixed-radix counter. Port it to a CUDA kernel and assign each thread a starting index; each thread iterates a chunk. The per-rect nibble candidate lists are small (≤6) and fit in constant memory.

Key steps:
1. Read per-rect nibble candidate lists from `img/sensible.json`.
2. Each thread:
   - Decodes its global index to a nibble vector via mixed-radix.
   - Builds the 32-byte private key.
   - Does secp256k1 scalar mult (can use cuECC or custom).
   - SHA-256 of compressed pubkey.
   - RIPEMD-160.
   - Compares to `TARGET_H160`.
3. Atomic write if hit.

## Files in this repo

- `img/crypto5fix.png` — source image from crypto.haluska.sk.
- `img/rects_v3.json` — per-rectangle pixel geometry (w_out, h_out, w_in, h_in).
- `img/sensible.json` — per-rectangle integer thickness solutions (pruned).
- `img/hypothesis_space.json` — earlier (looser) thickness solution list.
- `brute_tight_v2.py` — CPU brute forcer, fastest variant.
- `brute_force.py` — larger hypothesis coverage.
- `extract_v3.py` — OpenCV contour extraction used to build `rects_v3.json`.

## Caveats

- This is a 7-year-unsolved puzzle. Even with full pruned space covered, if the
  "thickness-as-nibble" hypothesis is wrong (e.g., the real decoding uses the
  author's undisclosed formula on pair-sums), brute forcing won't find it.
- The formula `-I *X+ LXIV /x/` and mini-puzzle `09111819 FIX 11122111` remain
  undeciphered. Any solver that assumes a wrong formula will cover the wrong
  space.
- Partial base58 prefix matches (e.g., "10 chars out of 33") are statistical
  noise, NOT signal of progress.
