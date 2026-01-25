"""
More creative approaches to crack the mini-puzzle.
Focus on dimensions, special numbers, and different orderings.
"""
import hashlib
import ecdsa
import base58
import math

# Rectangle data: (Outer, Inner, Shell)
# But we also need WIDTH and HEIGHT
# The original MATLAB extracted these - let me reconstruct approximate dimensions
# Area = Width * Height, so we can derive possible dimensions

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
KNOWN_BYTE = 0x77  # 119

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
    if KNOWN_BYTE not in byte_list:
        return False
    privkey_hex = ''.join(f'{b:02x}' for b in byte_list)
    addr_c = privkey_to_address(privkey_hex, True)
    addr_u = privkey_to_address(privkey_hex, False)
    if addr_c == TARGET or addr_u == TARGET:
        print(f"\n{'='*60}")
        print(f"SOLVED! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"{'='*60}")
        with open("C:/Users/Public/SOLUTION.txt", "w") as f:
            f.write(f"SOLVED: {desc}\nKey: {privkey_hex}\n")
        return True
    return False

def get_areas(area_type='shell', mult40=17, mult53=6):
    idx_map = {'outer': 0, 'inner': 1, 'shell': 2}
    idx = idx_map.get(area_type, 2)
    areas = [r[idx] for r in RECT_DATA]
    areas[39] *= mult40
    areas[52] *= mult53
    return areas

print("="*70)
print("CREATIVE APPROACHES TO MINI-PUZZLE")
print("="*70)

# =============================================================================
# APPROACH 1: The numbers 17 and 6 relate to sequences
# =============================================================================
print("\n[1] 17 and 6 in relation to sequences...")
# 17 could mean: use position 17 specially, or 1+7=8, or 17th byte
# 6 could mean: use position 6, or offset of 6

# What if 17 means "apply multiplier at positions where digit is 1, 7 times"
# And 6 means "apply at positions where digit is even, 6 times"

# =============================================================================
# APPROACH 2: Different byte order (reverse, interleave)
# =============================================================================
print("\n[2] Different byte orderings...")
areas = get_areas('shell', 17, 6)

for div in [8, 16, 32, 64]:
    # Standard order
    pairs = [(areas[i*2] + areas[i*2+1]) // div % 256 for i in range(32)]

    # Reversed
    pairs_rev = pairs[::-1]
    if check_key(pairs_rev, f"reversed_div{div}"):
        exit()

    # Interleaved (evens then odds)
    pairs_even = pairs[::2]
    pairs_odd = pairs[1::2]
    pairs_interleaved = pairs_even + pairs_odd
    if check_key(pairs_interleaved, f"interleaved_div{div}"):
        exit()

    # Every other byte swapped
    pairs_swapped = []
    for i in range(0, 32, 2):
        if i+1 < 32:
            pairs_swapped.extend([pairs[i+1], pairs[i]])
        else:
            pairs_swapped.append(pairs[i])
    if check_key(pairs_swapped, f"byte_swapped_div{div}"):
        exit()

# =============================================================================
# APPROACH 3: Use sqrt of areas (to get dimensions)
# =============================================================================
print("\n[3] Using square root (dimensions)...")
areas = get_areas('shell', 17, 6)

for div in [1, 2, 4, 8]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        # Approximate "width" using sqrt
        dim1 = int(math.sqrt(areas[idx1]))
        dim2 = int(math.sqrt(areas[idx2]))
        val = (dim1 + dim2) // div
        pairs.append(val % 256)
    if check_key(pairs, f"sqrt_div{div}"):
        exit()

# =============================================================================
# APPROACH 4: Specific positions from sequences
# =============================================================================
print("\n[4] Specific position mapping...")
# 09111819 could mean positions 0,9,11,18,19 (breaking differently)
# 11122111 could mean positions 11,12,21,11

pos1 = [0, 9, 11, 18, 19]
pos2 = [11, 12, 21, 11]
all_pos = pos1 + pos2

# Use these as special positions that get different treatment
areas = get_areas('shell', 17, 6)

for div in [8, 16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        if i in all_pos:
            # Different operation for special positions
            val = abs(areas[idx1] - areas[idx2]) // div
        else:
            val = (areas[idx1] + areas[idx2]) // div
        pairs.append(val % 256)
    if check_key(pairs, f"special_pos_div{div}"):
        exit()

# =============================================================================
# APPROACH 5: Encoding as column traversal indices
# =============================================================================
print("\n[5] Column-based traversal...")
# 09111819 = columns 0,9%8=1,1,1,1,8%8=0,1,9%8=1 for rows
# This suggests a mostly column-1 focused pattern

areas = get_areas('shell', 17, 6)

# Read by columns instead of rows
for div in [8, 16, 32, 64]:
    pairs = []
    for col in range(8):
        for row_pair in range(4):
            idx1 = row_pair * 2 * 8 + col
            idx2 = (row_pair * 2 + 1) * 8 + col
            val = (areas[idx1] + areas[idx2]) // div
            pairs.append(val % 256)
    if check_key(pairs, f"column_major_div{div}"):
        exit()

# =============================================================================
# APPROACH 6: Use modular arithmetic with LHIU values
# =============================================================================
print("\n[6] LHIU modular operations...")
# L=12, H=8, I=9, U=21

lhiu = [12, 8, 9, 21]
areas = get_areas('shell', 17, 6)

for op_idx, (mult, mod) in enumerate([(12, 8), (8, 9), (9, 21), (12, 21), (8, 12)]):
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        val = ((areas[idx1] + areas[idx2]) * mult) // mod
        pairs.append(val % 256)
    if check_key(pairs, f"lhiu_mult{mult}_div{mod}"):
        exit()

# =============================================================================
# APPROACH 7: Offset pattern from digit differences
# =============================================================================
print("\n[7] Digit differences as offsets...")
seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
# Differences: 9,-8,0,0,7,-7,8,-8,0,0,1,0,-1,0,0
diffs = [seq[i+1] - seq[i] for i in range(len(seq)-1)]

areas = get_areas('shell', 17, 6)

for div in [8, 16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        diff = diffs[i % len(diffs)]
        idx2 = (idx1 + 1 + abs(diff)) % 64
        val = (areas[idx1] + areas[idx2]) // div
        pairs.append(val % 256)
    if check_key(pairs, f"diff_offset_div{div}"):
        exit()

# =============================================================================
# APPROACH 8: Use both outer and shell together
# =============================================================================
print("\n[8] Combined outer+shell...")
outer = [r[0] for r in RECT_DATA]
shell = get_areas('shell', 17, 6)

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        # Outer from first, shell from second
        val = (outer[idx1] + shell[idx2]) // div
        pairs.append(val % 256)
    if check_key(pairs, f"outer_shell_div{div}"):
        exit()

# =============================================================================
# APPROACH 9: 17 and 6 as divisors in formula
# =============================================================================
print("\n[9] 17 and 6 as formula components...")
areas_raw = [r[2] for r in RECT_DATA]  # No multipliers

# Try: (area / 17) for first half, (area / 6) for second half
for base_div in [1, 8, 16]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        if i < 16:
            val = (areas_raw[idx1] + areas_raw[idx2]) // (17 * base_div)
        else:
            val = (areas_raw[idx1] + areas_raw[idx2]) // (6 * base_div)
        pairs.append(val % 256)
    if check_key(pairs, f"17_6_split_div{base_div}"):
        exit()

# =============================================================================
# APPROACH 10: ASCII interpretation of LHIU
# =============================================================================
print("\n[10] LHIU as ASCII operations...")
# L=76, H=72, I=73, U=85 in ASCII
ascii_vals = [76, 72, 73, 85]

areas = get_areas('shell', 17, 6)

for div in [8, 16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        ascii_mod = ascii_vals[i % 4]
        val = ((areas[idx1] + areas[idx2]) // div) ^ ascii_mod
        pairs.append(val % 256)
    if check_key(pairs, f"ascii_xor_div{div}"):
        exit()

# =============================================================================
# APPROACH 11: Treat 09111819 11122111 as a 16-digit key
# =============================================================================
print("\n[11] 16-digit key interpretation...")
key_digits = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

areas = get_areas('shell', 17, 6)

# XOR sum with corresponding key digit, scaled
for scale in [1, 8, 16, 32]:
    pairs = []
    for i in range(32):
        idx1, idx2 = i*2, i*2+1
        key = key_digits[i % 16]
        val = ((areas[idx1] + areas[idx2]) // 64 + key * scale)
        pairs.append(val % 256)
    if check_key(pairs, f"key_add_scale{scale}"):
        exit()

# =============================================================================
# APPROACH 12: Every possible 2-byte pattern brute force
# =============================================================================
print("\n[12] Expanded brute force...")
areas = get_areas('shell', 17, 6)

count = 0
# For the first byte, we know it could be influenced by rect 39+44 = 119
# So let's look at patterns where rect 39 and 44 are paired

# Find which pair index would contain rect 39
# If consecutive: pair 19 (indices 38,39)
# If we pair 39 with 44, we need a custom pattern

# Build a pattern where position 19 pairs rect 39 with 44
for div in [1, 2, 4, 8, 16, 32, 64, 128]:
    # Custom pairing: mostly consecutive, but pair 19 uses rect 39+44
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = i * 2 + 1
        # Override for position that should give 119
        if idx1 == 38 or idx1 == 39:
            idx1 = 39
            idx2 = 44
        val = (areas[idx1] + areas[idx2]) // div
        pairs.append(val % 256)
    if check_key(pairs, f"custom_39_44_div{div}"):
        exit()
    count += 1

# Also try putting 39+44 at different positions
for target_pos in range(32):
    pairs = []
    for i in range(32):
        if i == target_pos:
            idx1, idx2 = 39, 44
        else:
            idx1 = i * 2 if i < target_pos else (i * 2 + 2) % 64
            idx2 = i * 2 + 1 if i < target_pos else (i * 2 + 3) % 64
        val = (areas[idx1] + areas[idx2]) // 64
        pairs.append(val % 256)
    if check_key(pairs, f"pos{target_pos}_39_44"):
        exit()
    count += 1

print(f"\nTotal additional checks: {count}")
print("\nStill searching for the solution...")
print("\nRemaining ideas:")
print("  - Check for hidden data in image metadata/pixels")
print("  - The formula may involve more complex operations")
print("  - 'FIN' could mean 'Final' operation or 'Finish' marker")
