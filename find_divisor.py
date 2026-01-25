"""
Find what divisor would produce 119 (0x77) in the output
"""

RECT_DATA = [
    (6264, 3780, 2484), (3540, 2156, 1384), (5040, 3968, 1072), (2684, 1428, 1256),
    (3180, 1950, 1230), (3818, 2860, 958), (1152, 420, 732), (3015, 1755, 1260),
    (506, 72, 434), (480, 180, 300), (1504, 1170, 334), (3900, 2950, 950),
    (2132, 1950, 182), (850, 552, 298), (4293, 2457, 1836), (4214, 3096, 1118),
    (5913, 4425, 1488), (3358, 2420, 938), (1395, 609, 786), (2520, 1938, 582),
    (798, 330, 468), (1056, 240, 816), (2640, 1240, 1400), (3895, 2125, 1770),
    (4400, 3010, 1390), (2726, 1540, 1186), (5856, 4028, 1828), (2268, 1040, 1228),
    (3053, 1769, 1284), (4420, 2640, 1780), (3234, 1566, 1668), (5170, 3478, 1692),
    (704, 96, 608), (2107, 1521, 586), (3328, 2520, 808), (1568, 902, 666),
    (4453, 3213, 1240), (3550, 2332, 1218), (1472, 560, 912), (1139, 300, 839),
    (690, 30, 660), (1419, 961, 458), (3472, 2352, 1120), (2898, 1764, 1134),
    (672, 224, 448), (1173, 123, 1050), (2184, 1404, 780), (1581, 527, 1054),
    (7476, 6006, 1470), (2793, 1961, 832), (3484, 2530, 954), (5280, 4042, 1238),
    (126, 8, 118), (120, 32, 88), (3705, 2303, 1402), (5200, 3332, 1868),
    (5829, 4187, 1642), (2537, 2255, 282), (1632, 720, 912), (3894, 2296, 1598),
    (4130, 3762, 368), (2288, 768, 1520), (1380, 380, 1000), (1856, 1200, 656),
]

shell = [r[2] for r in RECT_DATA]
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

print("="*70)
print("FINDING DIVISORS THAT PRODUCE 119")
print("="*70)

# For each pair, find what divisor would give 119
print("\n[1] For each pair, what divisor gives 119?")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        print(f"\nMultipliers: rect40={mult40}, rect53={mult53}")
        for i in range(32):
            pair_sum = shell_m[i*2] + shell_m[i*2+1]
            # For sum / div = 119 (mod 256), we need:
            # sum / div = 119 + k*256 for some k >= 0
            # div = sum / (119 + k*256)
            for k in range(10):
                target = 119 + k * 256
                if pair_sum >= target:
                    div = pair_sum // target
                    if div > 0 and (pair_sum // div) % 256 == 119:
                        print(f"  Pair {i}: sum={pair_sum}, divisor={div} gives 119")

# For LXIV = 64, which pair sums give results near 119?
print("\n[2] With divisor 64, what values do we get?")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

sums = [shell_m[i*2] + shell_m[i*2+1] for i in range(32)]
results = [s // 64 % 256 for s in sums]

print("Pair sums and results with div 64:")
for i in range(32):
    print(f"  Pair {i}: sum={sums[i]}, div64={results[i]}")

# What would we need to add/subtract to get 119?
print("\n[3] Adjustments needed to get 119:")
for i in range(32):
    current = results[i]
    diff = 119 - current
    print(f"  Pair {i}: current={current}, need to add {diff} (or {diff % 256})")

# Find pairs where sum / 64 is close to 119
print("\n[4] Pairs closest to 119 with div 64:")
close_pairs = [(i, results[i], abs(results[i] - 119)) for i in range(32)]
close_pairs.sort(key=lambda x: x[2])
for i, val, diff in close_pairs[:10]:
    print(f"  Pair {i}: value={val}, diff={diff}")

# What if we use a different starting formula?
print("\n[5] Exploring sum relationships...")

# Rect 39 (40th) shell = 839
# Rect 52 (53rd) shell = 118
# 839 * 17 = 14263
# 118 * 6 = 708

# Pair 19 contains rect 38 and 39 (0-indexed)
# Pair 26 contains rect 52 and 53

print(f"Rect 39 shell (orig): {shell[39]}")
print(f"Rect 39 shell (x17): {shell[39] * 17}")
print(f"Rect 52 shell (orig): {shell[52]}")
print(f"Rect 52 shell (x6): {shell[52] * 6}")

# What pair index contains rect 39?
print(f"\nRect 39 is in pair {39 // 2} (with rect {38 if 39 % 2 else 40})")
print(f"Rect 52 is in pair {52 // 2} (with rect {52 if 52 % 2 == 0 else 53})")

# Pair 19: shell[38] + shell[39]*17 = 912 + 14263 = 15175
pair19_sum = shell[38] + shell[39] * 17
print(f"\nPair 19 sum (m17): {pair19_sum}")
print(f"  div 64: {pair19_sum // 64} = {pair19_sum // 64 % 256}")
print(f"  div 119: {pair19_sum // 119} = {pair19_sum // 119 % 256}")
print(f"  div 127: {pair19_sum // 127} = {pair19_sum // 127 % 256}")

# What divisor gives 119 for pair 19?
for d in range(1, 200):
    if (pair19_sum // d) % 256 == 119:
        print(f"  DIVISOR {d} GIVES 119!")

# Pair 26: shell[52]*6 + shell[53] = 708 + 88 = 796
pair26_sum = shell[52] * 6 + shell[53]
print(f"\nPair 26 sum (m6): {pair26_sum}")
print(f"  div 64: {pair26_sum // 64}")

for d in range(1, 200):
    if (pair26_sum // d) % 256 == 119:
        print(f"  DIVISOR {d} GIVES 119!")

# What about using 119 as a divisor?
print("\n[6] Using 119 as divisor...")
shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

pairs_119 = [(shell_m[i*2] + shell_m[i*2+1]) // 119 % 256 for i in range(32)]
print(f"Results: {pairs_119}")

# Check if 77 (hex of 119) appears
print(f"Contains 77: {77 in pairs_119}")
print(f"Contains 119: {119 in pairs_119}")
