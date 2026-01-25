# Zden Level 5 Bitcoin Puzzle Solver

## Overview

This repository contains extensive exploration scripts for solving the Zden Level 5 cryptocurrency puzzle. The puzzle encodes a 32-byte Bitcoin private key within 64 rectangles, with the target address:

```
1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7
```

## Puzzle Structure

### Rectangle Data
- 64 rectangles, each with 3 values: (outer_area, inner_area, shell_area)
- shell = outer - inner (frame area)

### Key Clues
1. **Mini-puzzle**: `09111819 FIX 11122111`
   - Digit sums: 30 + 10 = 40

2. **FIX = 39**: F(6) + I(9) + X(24) = 39

3. **17px line**: At position 40 (0-indexed as 39)

4. **Key discoveries**:
   - `shell[39] / 7 = 119 = 0x77` (exact!)
   - `shell[57] / 7 = 40 = 0x28` (exact!)

5. **Formula hint**: `-I *X+ LXIV /x/`

## Best Results Found

### 10 Character Match
- **Pattern**: Step-3 from position 57 with byte 23 set to 176
- **Key**: `28345d99883e87068642fc05fe565f82414096880ceae4b0c5afb42f2ad453c8`
- **Address**: `1DrNWtoGDjRE2kVfeuvXKyFESSD2HFNiw2`

### Standard Pairs Formula with FIX
- **Formula**: `(shell[i*2] + shell[i*2+1]) / 7` with `shell[39] *= 17`
- **Key**: `284c381c68b744a65ac3b7c470b4b5e0aad25f779f42d60648391dd312660dec`
- **Properties**: Byte 0 = 0x28, Byte 19 = 0x77

## Approaches Tested

### Formula Variations
- Pairs: (shell[2i] + shell[2i+1]) / divisor
- Single rectangles with step patterns
- Different divisors: 1-100+
- Different operations: add, subtract, XOR, multiply
- Multiplier at position 39: 17, 7, 10, etc.

### Pattern Approaches
- Step patterns (steps 2, 3, 17, 26 from various starts)
- Walk patterns based on digit sequence
- Spiral, diagonal, grid patterns
- Fibonacci indices

### Search Methods
- Exhaustive single/multi-byte modifications
- Genetic algorithms
- Hill climbing
- Random search with millions of trials

## Key Files

| File | Description |
|------|-------------|
| `step_pattern.py` | Step-based pattern exploration |
| `focused.py` | Focused search on best candidates |
| `targeted.py` | Clue-based targeted approaches |
| `walk_explore.py` | Rectangle walk patterns |
| `creative.py` | Creative/alternative approaches |
| `digit_mod.py` | Digit sequence interpretations |

## Rectangle Data

```python
RECT_DATA = [
    (6264, 3780, 2484), (3540, 2156, 1384), (5040, 3968, 1072), (2684, 1428, 1256),
    (3180, 1950, 1230), (3818, 2860, 958), (1152, 420, 732), (3015, 1755, 1260),
    # ... (64 total rectangles)
]
shell = [r[2] for r in RECT_DATA]  # Shell areas
```

## Target Address Analysis

```
Address: 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7
Hash160: 06c84797d2441393513e2169338e00cf2e755c8c
```

## Status

**UNSOLVED** - Despite testing millions of key variations across numerous formula interpretations, the exact solution has not been found. The puzzle likely requires:
- Additional context from original visual presentation
- A specific transformation not apparent from data alone
- Different interpretation of the formula hint

## Requirements

```
pip install ecdsa base58
```

## License

Educational/Research purposes only.
