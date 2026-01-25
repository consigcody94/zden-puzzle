"""
New approaches - thinking differently about the puzzle.
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
print("SOLVE V2 - NEW APPROACHES")
print("="*70)

# ============================================================================
# 1. Digit as direct second index
# ============================================================================
print("\n[1] Digit as second index...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        idx1 = i * 2
        idx2 = digit
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"digit_idx2_div{div}"):
            exit()

# ============================================================================
# 2. Mirror pairing: (i, 63-i)
# ============================================================================
print("\n[2] Mirror pairing...")

for div in [7, 10, 14]:
    pairs = []
    for i in range(32):
        idx1 = i
        idx2 = 63 - i
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"mirror_div{div}"):
            exit()

# ============================================================================
# 3. Multiplier at 38 instead of 39
# ============================================================================
print("\n[3] Multiplier at 38...")

for mult in range(2, 50):
    shell_m = shell.copy()
    shell_m[38] *= mult

    for div in [7, 10]:
        pairs = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if pairs[0] == 0x28 and 0x77 in pairs:
            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            print(f"  mult{mult} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"mult38_{mult}_div{div}"):
                exit()

# ============================================================================
# 4. All divisors 1-100
# ============================================================================
print("\n[4] All divisors...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in range(1, 101):
    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
        pairs.append(val)

    if check_key(pairs, f"div_{div}"):
        exit()

# Without multiplier
for div in range(1, 101):
    pairs = []
    for i in range(32):
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        pairs.append(val)

    if check_key(pairs, f"nomult_div_{div}"):
        exit()

print("  1-100: no solution")

# ============================================================================
# 5. All multipliers 1-200 at 39
# ============================================================================
print("\n[5] All multipliers at 39...")

for mult in range(1, 201):
    shell_m = shell.copy()
    shell_m[39] *= mult

    for div in [7, 10]:
        pairs = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"mult{mult}_div{div}"):
            exit()

print("  1-200: no solution")

# ============================================================================
# 6. Two multipliers at 39 and 57
# ============================================================================
print("\n[6] Two multipliers (39, 57)...")

for m39 in range(1, 25):
    for m57 in range(1, 25):
        shell_m = shell.copy()
        shell_m[39] *= m39
        shell_m[57] *= m57

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if check_key(pairs, f"m39_{m39}_m57_{m57}_div{div}"):
                exit()

print("  No solution")

# ============================================================================
# 7. Single-byte XOR on best key
# ============================================================================
print("\n[7] Single-byte XOR...")

shell_m = shell.copy()
shell_m[39] *= 17
base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

for xor_val in range(1, 256):
    pairs = [b ^ xor_val for b in base]
    if check_key(pairs, f"xor_{xor_val}"):
        exit()

print("  No solution")

# ============================================================================
# 8. Position-specific XOR
# ============================================================================
print("\n[8] Position-specific XOR...")

for pos in range(32):
    for xor_val in range(256):
        pairs = base.copy()
        pairs[pos] ^= xor_val
        if check_key(pairs, f"pos{pos}_xor{xor_val}"):
            exit()

print("  No solution")

# ============================================================================
# 9. Try adding constants
# ============================================================================
print("\n[9] Adding constants...")

for add_val in range(-128, 129):
    pairs = [(b + add_val) % 256 for b in base]
    if check_key(pairs, f"add_{add_val}"):
        exit()

print("  No solution")

# ============================================================================
# 10. Different formula: (s1 * s2) / divisor
# ============================================================================
print("\n[10] Multiplication formula...")

for div in [1000, 10000, 100000, 1000000]:
    pairs = []
    for i in range(32):
        val = (shell_m[i*2] * shell_m[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  s1*s2 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"mult_formula_div{div}"):
            exit()

# ============================================================================
# 11. Use outer values with multipliers
# ============================================================================
print("\n[11] Outer values...")

for mult in [1, 17]:
    outer_m = outer.copy()
    if mult > 1:
        outer_m[39] *= mult

    for div in range(10, 100, 5):
        pairs = []
        for i in range(32):
            val = (outer_m[i*2] + outer_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"outer_m{mult}_d{div}"):
            exit()

print("  No solution")

# ============================================================================
# 12. Inner values
# ============================================================================
print("\n[12] Inner values...")

for mult in [1, 17]:
    inner_m = inner.copy()
    if mult > 1:
        inner_m[39] *= mult

    for div in range(10, 100, 5):
        pairs = []
        for i in range(32):
            val = (inner_m[i*2] + inner_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"inner_m{mult}_d{div}"):
            exit()

print("  No solution")

# ============================================================================
# 13. Combined: outer + inner + shell
# ============================================================================
print("\n[13] Combined values...")

for div in range(20, 200, 10):
    pairs = []
    for i in range(32):
        val = (outer[i*2] + outer[i*2+1] + inner[i*2] + inner[i*2+1] + shell[i*2] + shell[i*2+1]) // div % 256
        pairs.append(val)

    if check_key(pairs, f"combined_d{div}"):
        exit()

print("  No solution")

# ============================================================================
# 14. Rotate/shift the key
# ============================================================================
print("\n[14] Rotations...")

for rot in range(1, 32):
    pairs = base[rot:] + base[:rot]
    if check_key(pairs, f"rot_{rot}"):
        exit()

    pairs = base[-rot:] + base[:-rot]
    if check_key(pairs, f"rot_neg_{rot}"):
        exit()

print("  No solution")

# ============================================================================
# 15. Byte reversal patterns
# ============================================================================
print("\n[15] Byte patterns...")

# Full reverse
pairs = base[::-1]
if check_key(pairs, "reversed"):
    exit()

# Swap halves
pairs = base[16:] + base[:16]
if check_key(pairs, "swap_halves"):
    exit()

# Interleave halves
pairs = []
for i in range(16):
    pairs.append(base[i])
    pairs.append(base[i + 16])
if check_key(pairs, "interleave"):
    exit()

print("  No solution")

print("\n" + "="*70)
print("V2 complete - no solution")
print("="*70)
