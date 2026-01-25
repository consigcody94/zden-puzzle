"""
FOCUSED SOLVER based on key findings:
1. Digit sums: 30 + 10 = 40 (points to rect 40!)
2. shell[39] / shell[52] = 839/118 ≈ 7 (the divisor!)
3. With mult17 at rect 39 and div7, position 19 = 119
4. 17 * 7 = 119 (0x77)

Key relationship: the 17px line and divisor 7 multiply to give 0x77!
"""
import hashlib
import ecdsa
import base58
import itertools

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

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

shell = [r[2] for r in RECT_DATA]
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

def privkey_to_address(privkey_bytes, compressed=True):
    try:
        sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compressed:
            if vk.pubkey.point.y() % 2 == 0:
                pubkey = b'\x02' + vk.to_string()[:32]
            else:
                pubkey = b'\x03' + vk.to_string()[:32]
        else:
            pubkey = b'\x04' + vk.to_string()
        sha256_hash = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        versioned = b'\x00' + pubkey_hash
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        return base58.b58encode(versioned + checksum).decode()
    except:
        return None

def check_key(byte_list, desc=""):
    if len(byte_list) != 32:
        return False
    if not all(0 <= b <= 255 for b in byte_list):
        return False
    privkey_bytes = bytes(byte_list)
    for compressed in [True, False]:
        addr = privkey_to_address(privkey_bytes, compressed)
        if addr == TARGET:
            print(f"\n{'='*60}")
            print(f"SOLVED! {desc}")
            print(f"Key: {privkey_bytes.hex()}")
            print(f"Compressed: {compressed}")
            print(f"{'='*60}")
            with open("C:/Users/Public/SOLUTION.txt", "w") as f:
                f.write(f"Solution: {desc}\n")
                f.write(f"Key: {privkey_bytes.hex()}\n")
            return True
    return False

print("="*70)
print("FOCUSED SOLVER")
print("="*70)
print("Key insight: 17 * 7 = 119 (0x77)")
print("shell[39]/shell[52] = 839/118 ~ 7")
print()

# ============================================================================
# Output the baseline key with m17/div7
# ============================================================================
print("[1] Baseline with mult17 at rect 39, divisor 7...")

shell_m = shell.copy()
shell_m[39] *= 17

pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
print(f"  Key bytes: {[hex(p) for p in pairs]}")
print(f"  Position of 0x77: {[i for i, p in enumerate(pairs) if p == 0x77]}")
check_key(pairs, "baseline_m17_div7")

# ============================================================================
# Try adding mult6 at rect 52
# ============================================================================
print("\n[2] With mult17 at rect 39 AND mult6 at rect 52...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
print(f"  Key bytes: {[hex(p) for p in pairs]}")
print(f"  Position of 0x77: {[i for i, p in enumerate(pairs) if p == 0x77]}")
check_key(pairs, "m17_m6_div7")

# ============================================================================
# Try different divisors
# ============================================================================
print("\n[3] Different divisors with m17/m6...")

for div in [7, 17, 64, 119, 127]:
    shell_m = shell.copy()
    shell_m[39] *= 17
    shell_m[52] *= 6

    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  div{div}: 0x77 at positions {has_77}")
        check_key(pairs, f"m17_m6_div{div}")

# ============================================================================
# The formula might be: (sum + 64) // 7 or similar with LXIV
# ============================================================================
print("\n[4] Including LXIV (64) in formula...")

for add_val in [0, 32, 64, -64]:
    for div in [7, 64, 127]:
        shell_m = shell.copy()
        shell_m[39] *= 17
        shell_m[52] *= 6

        pairs = [(shell_m[i*2] + shell_m[i*2+1] + add_val) // div % 256 for i in range(32)]
        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  add{add_val} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"m17_m6_add{add_val}_div{div}"):
                exit()

# ============================================================================
# What if we need to apply the formula: (-I * X + LXIV) / x
# ============================================================================
print("\n[5] Formula: (-Inner * X + 64) / X...")

for x in [7, 10, 17]:
    shell_m = shell.copy()
    inner_m = inner.copy()
    shell_m[39] *= 17
    shell_m[52] *= 6
    inner_m[39] *= 17
    inner_m[52] *= 6

    pairs = []
    for i in range(32):
        I = inner_m[i*2] + inner_m[i*2+1]
        result = abs((-I * x + 64) // x) % 256
        pairs.append(result)

    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  x={x}: 0x77 at {has_77}")
        if check_key(pairs, f"formula_x{x}_m17_m6"):
            exit()

# ============================================================================
# Try different area components
# ============================================================================
print("\n[6] Using Outer areas instead of Shell...")

for div in [7, 64, 127]:
    outer_m = outer.copy()
    outer_m[39] *= 17
    outer_m[52] *= 6

    pairs = [(outer_m[i*2] + outer_m[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  Outer div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"outer_m17_m6_div{div}"):
            exit()

print("\n[7] Using Inner areas...")

for div in [7, 64, 127]:
    inner_m = inner.copy()
    inner_m[39] *= 17
    inner_m[52] *= 6

    pairs = [(inner_m[i*2] + inner_m[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  Inner div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"inner_m17_m6_div{div}"):
            exit()

# ============================================================================
# Try combinations of operations at different positions
# ============================================================================
print("\n[8] Apply mult17 to different positions...")

# What if 17 should be applied elsewhere, not just rect 39?
for pos in range(64):
    shell_m = shell.copy()
    shell_m[pos] *= 17

    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]

    if has_77 and pos != 39:  # We already know 39 works
        print(f"  mult17 at pos {pos}: 0x77 at {has_77}")
        if check_key(pairs, f"mult17_pos{pos}_div7"):
            exit()

# ============================================================================
# Try XOR with 119 at specific positions
# ============================================================================
print("\n[9] XOR with 119 at specific positions...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# XOR positions where digit != 1 in mini-puzzle
xor_positions = [0, 1, 5, 7, 11, 12]  # From earlier analysis

for num_xor in range(1, len(xor_positions) + 1):
    for combo in itertools.combinations(xor_positions, num_xor):
        pairs = base.copy()
        for pos in combo:
            if pos < 32:
                pairs[pos] ^= 119

        if 0x77 in pairs:
            if check_key(pairs, f"xor77_at_{combo}_m17_m6_div7"):
                exit()

# ============================================================================
# Try subtraction instead of addition for the pair operation
# ============================================================================
print("\n[10] Subtraction instead of addition...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

for div in [7, 64, 127]:
    pairs = [abs(shell_m[i*2] - shell_m[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  Subtract div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"subtract_m17_m6_div{div}"):
            exit()

# ============================================================================
# The "following" hint with m17/m6
# ============================================================================
print("\n[11] Non-consecutive pairing with m17/m6...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

for skip in [2, 7, 8, 9]:
    for div in [7, 64, 127]:
        pairs = []
        for i in range(32):
            idx1 = i
            idx2 = (i + skip) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // div % 256
            pairs.append(val)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  skip{skip} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"skip{skip}_m17_m6_div{div}"):
                exit()

# ============================================================================
# Maybe mult17 applies to the SUM, not individual rect
# ============================================================================
print("\n[12] Apply mult17 to the sum...")

for div in [7, 64, 127]:
    pairs = []
    for i in range(32):
        pair_sum = shell[i*2] + shell[i*2+1]
        if i == 19:  # Position where we want 119
            pair_sum *= 17
        val = pair_sum // div % 256
        pairs.append(val)

    has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  mult17_sum_pos19 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"mult17_sum_pos19_div{div}"):
            exit()

# ============================================================================
# What if the key needs to be reversed or reordered?
# ============================================================================
print("\n[13] Reversed byte order...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

for div in [7, 64, 127]:
    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
    pairs_rev = pairs[::-1]

    if 0x77 in pairs_rev:
        if check_key(pairs_rev, f"reversed_m17_m6_div{div}"):
            exit()

# ============================================================================
# Try different byte orderings
# ============================================================================
print("\n[14] Different byte orderings...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Swap halves
swapped = base[16:] + base[:16]
if check_key(swapped, "swapped_halves_m17_m6_div7"):
    exit()

# Interleave
interleaved = []
for i in range(16):
    interleaved.append(base[i])
    interleaved.append(base[31-i])
if check_key(interleaved, "interleaved_m17_m6_div7"):
    exit()

print("\n" + "="*70)
print("SUMMARY OF KEY CONFIGURATION:")
print("="*70)
print("Best result: mult17 at rect 39, divisor 7 -> byte[19] = 0x77")
print()
print("Full key with this config:")
shell_m = shell.copy()
shell_m[39] *= 17
pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
hex_key = ''.join(f'{p:02x}' for p in pairs)
print(f"Hex: {hex_key}")
print(f"Bytes: {pairs}")

print("\nFocused solver complete.")
