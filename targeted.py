"""
Targeted approach based on specific clue interpretations.

Clues:
- 09111819 FIX 11122111
- FIX = 39 (F=6, I=9, X=24)
- 17px line at rect 40 (index 39)
- shell[39]/7 = 119 = 0x77
- shell[57]/7 = 40 = 0x28
- Digit sums: 30 (first part) + 10 (second part) = 40

Key insight: What if the digits directly tell us the rectangle indices?
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

def count_match(addr):
    if not addr:
        return 0
    return sum(1 for a, b in zip(addr, TARGET) if a == b)

print("="*70)
print("TARGETED CLUE-BASED APPROACHES")
print("="*70)

# ============================================================================
# 1. Interpretation: digits as pair ordering
# ============================================================================
print("\n[1] Digits as pair indices (two-digit)...")

# 09111819 FIX 11122111 -> pairs 09, 11, 18, 19, FIX(=39), 11, 12, 21, 11
# These could be the pair indices for the first 9 bytes
pair_indices = [9, 11, 18, 19, 39, 11, 12, 21, 11]

for div in [7, 10]:
    key = []
    # Use specified pairs for first 9 bytes
    for idx in pair_indices[:9]:
        if idx < 32:  # It's a pair index
            val = (shell[idx*2] + shell[idx*2+1]) // div % 256
        else:  # idx=39 is a single rect
            val = shell[idx] // div % 256
        key.append(val)

    # Fill rest normally
    for i in range(9, 32):
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Pair indices div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"pair_indices_div{div}"):
        exit()

# ============================================================================
# 2. Interpretation: digits control which rect in pair to use
# ============================================================================
print("\n[2] Digits control pair selection...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

for div in [7, 10]:
    key = []
    for i in range(32):
        digit = all_digits[i % 16]
        # 0 = use first rect, 1 = use second, 2 = use both, etc.
        if digit == 0:
            val = shell[i*2] // div % 256
        elif digit == 1:
            val = shell[i*2 + 1] // div % 256
        elif digit == 2:
            val = (shell[i*2] + shell[i*2+1]) // div % 256
        elif digit == 8:
            val = (shell[i*2] * shell[i*2+1]) // (div * 100) % 256
        elif digit == 9:
            val = abs(shell[i*2] - shell[i*2+1]) // div % 256
        else:
            val = (shell[i*2] + shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Digit control div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"digit_control_div{div}"):
        exit()

# ============================================================================
# 3. FIX at position 39: multiply, then pair at that position
# ============================================================================
print("\n[3] FIX modifies pair 19 (which uses rects 38,39)...")

for mult in [17, 7, 10, 6, 9, 24]:
    shell_m = shell.copy()
    shell_m[39] *= mult

    for div in [7, 10]:
        key = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            key.append(val)

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 3:
            print(f"  mult{mult} div{div}: {match} chars - {addr[:10]}...")
        if check_key(key, f"fix_mult{mult}_div{div}"):
            exit()

# ============================================================================
# 4. Sort rectangles by shell value, then take key
# ============================================================================
print("\n[4] Sorted rectangles...")

# Sort by shell value
sorted_indices = sorted(range(64), key=lambda i: shell[i])
print(f"  Smallest: {sorted_indices[:5]}, Largest: {sorted_indices[-5:]}")

for div in [7, 10]:
    key = [shell[sorted_indices[i]] // div % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    print(f"  Smallest 32 div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"sorted_small_div{div}"):
        exit()

    key = [shell[sorted_indices[63-i]] // div % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    print(f"  Largest 32 div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"sorted_large_div{div}"):
        exit()

# ============================================================================
# 5. Interleave based on digit sequence
# ============================================================================
print("\n[5] Interleaved with digit pattern...")

for div in [7, 10]:
    key = []
    for i in range(32):
        d = all_digits[i % 16]
        if d % 2 == 0:
            val = (shell[i] + shell[63-i]) // div % 256
        else:
            val = abs(shell[i] - shell[63-i]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Mirror interleave div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"mirror_interleave_div{div}"):
        exit()

# ============================================================================
# 6. 30 and 10 (digit sums) as key parameters
# ============================================================================
print("\n[6] Digit sums 30 and 10...")

# Use 30 for first half, 10 for second half
for op in ['div', 'add', 'mult']:
    key = []
    for i in range(32):
        base = (shell[i*2] + shell[i*2+1]) // 7
        if i < 16:
            modifier = 30
        else:
            modifier = 10

        if op == 'div':
            val = base // modifier % 256
        elif op == 'add':
            val = (base + modifier) % 256
        else:
            val = (base * modifier) % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  30/10 {op}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"digitsum_{op}"):
        exit()

# ============================================================================
# 7. The 17 from "17px" as key multiplier
# ============================================================================
print("\n[7] 17px variations...")

# 17 appears as the line thickness - maybe multiply by 17 at some point
for pos in range(64):
    for div in [7, 10]:
        shell_m = shell.copy()
        shell_m[pos] *= 17

        key = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            key.append(val)

        if check_key(key, f"17x_pos{pos}_div{div}"):
            exit()

# ============================================================================
# 8. Reading the digits as a rectangle walk
# ============================================================================
print("\n[8] Rectangle walk from digits...")

# Start at rect 0, walk by digit amounts
for start in range(64):
    for div in [7, 10]:
        key = []
        pos = start
        for i in range(32):
            key.append(shell[pos] // div % 256)
            digit = all_digits[i % 16]
            pos = (pos + digit + 1) % 64

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 4:
            print(f"  Walk from {start} div{div}: {match} chars")
        if check_key(key, f"walk_{start}_div{div}"):
            exit()

# ============================================================================
# 9. Exhaustive two-rect formula with FIX
# ============================================================================
print("\n[9] Two special rects + formula...")

# shell[39]/7 = 119 = 0x77
# shell[57]/7 = 40 = 0x28

# Try different positions for these two values
for pos1 in range(32):
    for pos2 in range(32):
        if pos1 == pos2:
            continue

        for div in [7, 10]:
            key = []
            for i in range(32):
                if i == pos1:
                    val = 0x28  # From shell[57]
                elif i == pos2:
                    val = 0x77  # From shell[39]
                else:
                    val = (shell[i*2] + shell[i*2+1]) // div % 256
                key.append(val)

            if check_key(key, f"fixed_28_{pos1}_77_{pos2}_div{div}"):
                exit()

# ============================================================================
# 10. Binary interpretation of digit sequence
# ============================================================================
print("\n[10] Binary interpretation...")

# 09111819 = binary indicator?
# 11122111 = another indicator?

# Convert to binary-ish: 0 = use sum, 1 = use diff
for div in [7, 10]:
    key = []
    for i in range(32):
        d = all_digits[i % 16]
        if d == 0:
            val = (shell[i*2] + shell[i*2+1]) // div % 256
        else:
            val = abs(shell[i*2] - shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Binary ops div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"binary_ops_div{div}"):
        exit()

# ============================================================================
# 11. Maybe the solution uses a specific well-known divisor
# ============================================================================
print("\n[11] Well-known divisor search...")

known_divisors = [
    7,  # Days in week, luck
    10, # Decimal
    12, # Months
    13, # Bad luck
    17, # From puzzle
    24, # Hours
    26, # Letters
    32, # Half of 64
    39, # FIX
    40, # Digit sum
    52, # Weeks
    64, # Rects
    256, # Byte
]

for d in known_divisors:
    key = [(shell[i*2] + shell[i*2+1]) // d % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    print(f"  div {d}: {match} chars - {addr[:10] if addr else 'None'}...")
    if check_key(key, f"known_div_{d}"):
        exit()

print("\n" + "="*70)
print("Targeted approaches complete")
print("="*70)
