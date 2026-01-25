"""
More formula variations based on the clues.

Key observations:
- FIX = 39 (F=6, I=9, X=24)
- 17px line at rect 40
- Digit sums: 30, 10, total 40
- shell[39]/7 = 119 = 0x77 exactly
- shell[57]/7 = 40 = 0x28 exactly

What if the formula is:
- Use specific rectangles at specific positions?
- Or the bytes come from different calculations?
"""
import hashlib
import ecdsa
import base58

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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

print("="*70)
print("MORE FORMULA VARIATIONS")
print("="*70)

# ============================================================================
# 1. Use single rects at positions 39 and 57 for key bytes
# ============================================================================
print("\n[1] Position-specific single rects...")

# shell[39]/7 = 119 = 0x77
# shell[57]/7 = 40 = 0x28
print(f"shell[39] = {shell[39]}, /7 = {shell[39]//7}")
print(f"shell[57] = {shell[57]}, /7 = {shell[57]//7}")

# Build key: byte i comes from shell[(i + offset) % 64] / 7
for offset in range(64):
    pairs = [shell[(i + offset) % 64] // 7 % 256 for i in range(32)]
    if pairs[0] == 0x28 and 0x77 in pairs:
        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        print(f"  Offset {offset}: 0x77 at {has_77}")
        if check_key(pairs, f"single_offset_{offset}"):
            exit()

# ============================================================================
# 2. Mix of operations
# ============================================================================
print("\n[2] Position-dependent operations...")

for base_div in [7, 10]:
    for mod_offset in [0, 1, 2, 3]:
        pairs = []
        for i in range(32):
            digit = all_digits[i % 16]
            idx = i * 2

            # Different operation based on position
            if i % 4 == mod_offset:
                val = shell[idx] // base_div % 256
            else:
                val = (shell[idx] + shell[idx+1]) // base_div % 256

            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77 and pairs[0] == 0x28:
            print(f"  div{base_div} mod{mod_offset}: 0x77 at {has_77}")
            if check_key(pairs, f"mix_{base_div}_{mod_offset}"):
                exit()

# ============================================================================
# 3. Use the FIX position (39) differently
# ============================================================================
print("\n[3] FIX-centric formulas...")

# Every byte involves rect 39
for div in [7, 10]:
    pairs = []
    for i in range(32):
        # Pair each position with rect 39
        val = (shell[i * 2] + shell[39]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  pair_with_39 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"fix39_div{div}"):
            exit()

# XOR with shell[39]
for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = ((shell[i * 2] + shell[i * 2 + 1]) // div) ^ (shell[39] // div)
        pairs.append(val % 256)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  xor_shell39 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"xor39_div{div}"):
            exit()

# ============================================================================
# 4. Apply the digit sum values
# ============================================================================
print("\n[4] Digit sum application...")

# 30 and 10 as operations
for mode in ['mult', 'add', 'div']:
    pairs = []
    for i in range(32):
        base_val = (shell[i*2] + shell[i*2+1]) // 7

        if mode == 'mult':
            if i < 16:
                val = (base_val * 30) % 256
            else:
                val = (base_val * 10) % 256
        elif mode == 'add':
            if i < 16:
                val = (base_val + 30) % 256
            else:
                val = (base_val + 10) % 256
        else:  # div
            if i < 16:
                val = base_val // 30 % 256
            else:
                val = base_val // 10 % 256

        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  mode={mode}: 0x77 at {has_77}")
        if check_key(pairs, f"digitsum_{mode}"):
            exit()

# ============================================================================
# 5. Bit manipulation
# ============================================================================
print("\n[5] Bit manipulation...")

shell_m = shell.copy()
shell_m[39] *= 17
base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Rotate bits in each byte
for rot in range(1, 8):
    pairs = []
    for b in base:
        rotated = ((b << rot) | (b >> (8 - rot))) & 0xFF
        pairs.append(rotated)
    if check_key(pairs, f"rot_left_{rot}"):
        exit()

    pairs = []
    for b in base:
        rotated = ((b >> rot) | (b << (8 - rot))) & 0xFF
        pairs.append(rotated)
    if check_key(pairs, f"rot_right_{rot}"):
        exit()

print("  No solution")

# ============================================================================
# 6. Different interpretation of "non-consecutive following"
# ============================================================================
print("\n[6] Alternative 'following' interpretations...")

# Each rect follows the previous by digit amount
for start in [0, 39, 57]:
    for div in [7, 10]:
        pairs = []
        idx = start
        used = set()
        for i in range(32):
            digit = all_digits[i % 16]
            while idx in used and len(used) < 64:
                idx = (idx + 1) % 64
            used.add(idx)
            val = shell[idx] // div % 256
            pairs.append(val)
            idx = (idx + digit + 1) % 64

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77 and pairs[0] == 0x28:
            print(f"  following from {start} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"follow_{start}_div{div}"):
                exit()

# ============================================================================
# 7. Use all three values (outer, inner, shell)
# ============================================================================
print("\n[7] Three-value combinations...")

for div in [10, 20, 30]:
    pairs = []
    for i in range(32):
        # Average of three values
        val = (outer[i] + inner[i] + shell[i]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  O+I+S single div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"ois_single_div{div}"):
            exit()

# ============================================================================
# 8. Modular exponentiation
# ============================================================================
print("\n[8] Modular exponentiation...")

for exp in [2, 3, 7, 17]:
    pairs = []
    for i in range(32):
        val = pow(shell[i], exp, 256)
        pairs.append(val)

    if 0x77 in pairs:
        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        print(f"  shell^{exp} mod 256: 0x77 at {has_77}")
        if check_key(pairs, f"exp_{exp}"):
            exit()

# ============================================================================
# 9. Linear combination with specific coefficients
# ============================================================================
print("\n[9] Linear combinations...")

for coef in [(1, 1), (1, 2), (2, 1), (7, 10), (10, 7), (17, 7), (7, 17)]:
    a, b = coef
    for div in [7, 10, 17]:
        pairs = []
        for i in range(32):
            val = (shell[i*2] * a + shell[i*2+1] * b) // div % 256
            pairs.append(val)

        if 0x28 in pairs and 0x77 in pairs:
            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            first_28 = pairs.index(0x28) if 0x28 in pairs else -1
            print(f"  coef {a},{b} div{div}: 0x28 at {first_28}, 0x77 at {has_77}")
            if check_key(pairs, f"linear_{a}_{b}_div{div}"):
                exit()

# ============================================================================
# 10. Formula: (a - b) * c + d
# ============================================================================
print("\n[10] Difference formula...")

for mult in [1, 7, 10, 17]:
    for add in [0, 39, 64]:
        pairs = []
        for i in range(32):
            diff = shell[i*2] - shell[i*2+1]
            val = (diff * mult + add) // 7 % 256
            pairs.append(val)

        if 0x77 in pairs:
            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            print(f"  (s1-s2)*{mult}+{add}/7: 0x77 at {has_77}")
            if check_key(pairs, f"diff_{mult}_{add}"):
                exit()

print("\n" + "="*70)
print("More formulas complete - no solution")
print("="*70)
