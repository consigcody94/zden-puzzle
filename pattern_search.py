"""
Search for patterns and try unusual combinations
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

def privkey_to_address(privkey_hex, compressed=True):
    try:
        privkey_bytes = bytes.fromhex(privkey_hex)
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
    privkey_hex = ''.join(f'{b:02x}' for b in byte_list)
    addr_c = privkey_to_address(privkey_hex, True)
    addr_u = privkey_to_address(privkey_hex, False)
    if addr_c == TARGET or addr_u == TARGET:
        print(f"\n{'='*60}")
        print(f"SOLVED! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"{'='*60}")
        return True
    return False

outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]
shell = [r[2] for r in RECT_DATA]

# Apply standard multipliers
shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

print("="*70)
print("PATTERN SEARCH")
print("="*70)

# ============================================================================
# Use INNER areas (not just shell)
# ============================================================================
print("\n[1] Using INNER areas...")

inner_m = inner.copy()
inner_m[39] *= 17
inner_m[52] *= 6

for div in [16, 32, 64, 128]:
    pairs = [(inner_m[i*2] + inner_m[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Inner div{div}: Contains 119")
        if check_key(pairs, f"inner_div{div}"):
            exit()

# ============================================================================
# Use OUTER areas
# ============================================================================
print("\n[2] Using OUTER areas...")

outer_m = outer.copy()
outer_m[39] *= 17
outer_m[52] *= 6

for div in [32, 64, 128, 256]:
    pairs = [(outer_m[i*2] + outer_m[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Outer div{div}: Contains 119")
        if check_key(pairs, f"outer_div{div}"):
            exit()

# ============================================================================
# Combine O, I, S in different ways
# ============================================================================
print("\n[3] Combining O, I, S...")

for div in [64, 128]:
    # O + I per pair
    pairs = [(outer[i*2] + inner[i*2+1]) // div % 256 for i in range(32)]
    if check_key(pairs, f"outer_inner_div{div}"):
        exit()

    # O - I (should equal S, but let's verify pattern)
    pairs = [(outer[i*2] - inner[i*2] + outer[i*2+1] - inner[i*2+1]) // div % 256 for i in range(32)]
    if check_key(pairs, f"o_minus_i_div{div}"):
        exit()

    # (O + I + S) combined
    pairs = [(outer[i*2] + inner[i*2] + shell[i*2] + outer[i*2+1] + inner[i*2+1] + shell[i*2+1]) // (div * 3) % 256 for i in range(32)]
    if check_key(pairs, f"all_combined_div{div}"):
        exit()

# ============================================================================
# Look at ratios
# ============================================================================
print("\n[4] Area ratios...")

for div in [1, 10, 100]:
    pairs = []
    for i in range(32):
        if inner[i*2] > 0 and inner[i*2+1] > 0:
            ratio1 = outer[i*2] * 100 // inner[i*2]
            ratio2 = outer[i*2+1] * 100 // inner[i*2+1]
            val = (ratio1 + ratio2) // div
            pairs.append(val % 256)
        else:
            pairs.append(0)

    if 119 in pairs:
        print(f"  Ratios div{div}: Contains 119")
        if check_key(pairs, f"ratios_div{div}"):
            exit()

# ============================================================================
# Single rectangle bytes
# ============================================================================
print("\n[5] Single rectangle (not pairs)...")

# Maybe it's one byte per rectangle, not per pair
for div in [16, 32, 64]:
    pairs = [shell_m[i] // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Single rect div{div}: Contains 119")
        if check_key(pairs, f"single_div{div}"):
            exit()

    # Skip every other
    pairs = [shell_m[i*2] // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Even rects div{div}: Contains 119")
        if check_key(pairs, f"even_div{div}"):
            exit()

# ============================================================================
# Hash-based derivation
# ============================================================================
print("\n[6] Hash-based approaches...")

# SHA256 of shell data
shell_bytes = b''.join(s.to_bytes(4, 'big') for s in shell_m)
hash1 = hashlib.sha256(shell_bytes).digest()
pairs = list(hash1)
print(f"  SHA256 of shell data: {pairs[:16]}...")
if check_key(pairs, "sha256_shell"):
    exit()

# MD5
hash2 = hashlib.md5(shell_bytes).digest()
pairs = list(hash2) * 2  # MD5 is 16 bytes, need 32
if check_key(pairs, "md5_shell_doubled"):
    exit()

# ============================================================================
# Bit manipulation
# ============================================================================
print("\n[7] Bit extraction...")

for bit_pos in range(4, 12):
    pairs = [((shell_m[i*2] + shell_m[i*2+1]) >> bit_pos) & 0xFF for i in range(32)]
    if 119 in pairs:
        print(f"  Bit shift {bit_pos}: Contains 119")
        if check_key(pairs, f"bitshift_{bit_pos}"):
            exit()

# ============================================================================
# Weighted combinations using 17 and 6
# ============================================================================
print("\n[8] Weighted with 17 and 6...")

for div in [64, 128, 256]:
    # Weight first rect by 17, second by 6
    pairs = [(shell[i*2] * 17 + shell[i*2+1] * 6) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  17/6 weighted div{div}: Contains 119")
        if check_key(pairs, f"weighted_17_6_div{div}"):
            exit()

    # Reverse weights
    pairs = [(shell[i*2] * 6 + shell[i*2+1] * 17) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  6/17 weighted div{div}: Contains 119")
        if check_key(pairs, f"weighted_6_17_div{div}"):
            exit()

# ============================================================================
# Using the special rectangle values directly
# ============================================================================
print("\n[9] Special rectangles #40 and #53...")

# Rectangle 39 (index) original shell = 839
# Rectangle 52 (index) original shell = 118
rect40_orig = shell[39]  # 839
rect53_orig = shell[52]  # 118

print(f"  Rect #40 shell: {rect40_orig}")
print(f"  Rect #53 shell: {rect53_orig}")
print(f"  Sum: {rect40_orig + rect53_orig}")
print(f"  Product: {rect40_orig * rect53_orig}")

# 118 is very close to 119 (0x77)!
print(f"  Note: Rect #53 shell = 118, which is 0x76 (one less than 0x77)")

# Try without any multipliers but shift rect53 by 1
shell_special = shell.copy()
shell_special[52] += 1  # Make it exactly 119

for div in [1, 8, 16, 32, 64]:
    pairs = [(shell_special[i*2] + shell_special[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Special+1 div{div}: Contains 119")
        if check_key(pairs, f"special_plus1_div{div}"):
            exit()

# ============================================================================
# FIN could mean "subtract" or "negate"
# ============================================================================
print("\n[10] FIN as negation/subtraction...")

seq1 = [0,9,1,1,1,8,1,9]
seq2 = [1,1,1,2,2,1,1,1]

for div in [32, 64]:
    pairs = []
    for i in range(32):
        val1 = shell_m[i*2]
        val2 = shell_m[i*2+1]
        if i < 16:
            # Before FIN: add
            val = val1 + val2
        else:
            # After FIN: subtract
            val = abs(val1 - val2)
        pairs.append((val // div) % 256)

    if check_key(pairs, f"fin_negate_div{div}"):
        exit()

print("\nPattern search complete.")
