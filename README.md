# 🔐 Zden Level 5 Bitcoin Puzzle Solver

> **The Hunt for the Hidden Key** - Decoding 64 rectangles to find a 32-byte Bitcoin private key

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![Status](https://img.shields.io/badge/Status-Unsolved-red.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)]()

## 🎯 The Target

```
Address: 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7
```

A vanity address starting with "crypto" - somewhere in 64 nested rectangles lies the key to unlock it.

---

## 🧩 The Puzzle

### What We Have
- **64 Rectangles** - Each defined by `(outer_area, inner_area, shell_area)`
- **A Mini-Puzzle**: `09111819 FIX 11122111`
- **A Formula Hint**: `-I *X+ LXIV /x/`
- **A 17px Thick Line** at rectangle 40

### The Breakthrough Discoveries 🔍

| Discovery | Value | Significance |
|-----------|-------|--------------|
| `shell[39] / 7` | **119 = 0x77** | Exact division! |
| `shell[57] / 7` | **40 = 0x28** | Also exact! |
| FIX decoded | **F(6) + I(9) + X(24) = 39** | Points to rect 40! |
| Digit sums | **30 + 10 = 40** | Matches 0x28! |

---

## 🏆 Best Results

### 10 Character Match
```
Pattern: Step-3 from position 57, byte[23] = 176
Key:     28345d99883e87068642fc05fe565f82414096880ceae4b0c5afb42f2ad453c8
Address: 1DrNWtoGDjRE2kVfeuvXKyFESSD2HFNiw2
         ^^^^^^^^^^
         10 chars match!
```

### The Promising Key Structure
```
With FIX formula: (shell + shell[39]*17) / 7
Key:    284c381c68b744a65ac3b7c470b4b5e0aad25f779f42d60648391dd312660dec
        ^^                              ^^
        0x28 at byte 0                  0x77 at byte 19
```

---

## 🛠️ Approaches Tested

### Mathematical Formulas
```python
# Standard pairs
(shell[2i] + shell[2i+1]) / div

# FIX modification
shell[39] *= 17

# Step patterns
indices = [(start + i * step) % 64 for i in range(32)]
```

### Algorithms Deployed
- 🧬 **Genetic Algorithms** - Evolution of key candidates
- 🏔️ **Hill Climbing** - Local optimization
- 🎲 **Monte Carlo** - Millions of random trials
- 🔄 **Exhaustive Search** - Systematic byte modifications

### Pattern Variations
| Pattern | Description |
|---------|-------------|
| Step-2 | Every 2nd rectangle |
| Step-3 | Every 3rd rectangle |
| Step-17 | Aligned with 17px hint |
| Step-26 | Mirror of 64-38 |
| Walk | Following digit sequence |
| Spiral | 8x8 grid spiral read |

---

## 📊 The Data

```python
RECT_DATA = [
    (6264, 3780, 2484),  # Rectangle 0
    (3540, 2156, 1384),  # Rectangle 1
    # ... 62 more ...
    (1856, 1200, 656),   # Rectangle 63
]

# The magic numbers
shell[39] = 839   # 839 / 7 = 119.857... → 119 = 0x77 = 'w'
shell[57] = 282   # 282 / 7 = 40.28...   → 40  = 0x28
```

---

## 🚀 Quick Start

```bash
# Install dependencies
pip install ecdsa base58

# Run a solver
python focused.py

# Try the step-3 pattern
python step_pattern.py
```

---

## 📁 Key Files

| File | Purpose |
|------|---------|
| `focused.py` | Best candidate optimization |
| `step_pattern.py` | Step-based index patterns |
| `walk_explore.py` | Digit-guided traversal |
| `creative.py` | Alternative approaches |
| `digit_mod.py` | Mini-puzzle interpretations |

---

## 🤔 The Mystery Remains

Despite testing **millions of combinations**, the exact solution remains elusive. The puzzle likely requires:

1. 🖼️ **Visual context** from the original puzzle image
2. 🔑 **Hidden transformation** not apparent from data alone
3. 🧮 **Specific interpretation** of the formula hint

---

## 🎮 Want to Try?

1. Fork this repo
2. Study the patterns in `analyze_target.py`
3. Run `python focused.py` and see if you can beat 10 character matches!

---

## 📜 License

MIT - Crack it if you can! 🔓

---

<p align="center">
  <i>The key is out there. In 64 rectangles. Waiting to be found.</i>
</p>
