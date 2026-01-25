"""
Deep dive into cracking the mini-puzzle:
  09111819 FIN 11122111
  |-I  xN+  LHIU  /x?

Focus on finding the pattern that produces 0x77 at some position.
"""
import hashlib
import ecdsa
import base58
import itertools
from typing import List, Tuple

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
        print(f"Bytes: {byte_list}")
        print(f"{'='*60}")
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
print("MINI-PUZZLE DEEP ANALYSIS")
print("="*70)

# =============================================================================
# INTERPRETATION 1: Numbers as (row, col) coordinates
# =============================================================================
print("\n[1] Numbers as row,col coordinates in 8x8 grid...")
# 09111819 -> (0,9) invalid, or (0,9%8)=(0,1), (1,1), (1,8%8)=(1,0), (1,9%8)=(1,1)
# Let's try: split into pairs and use as (row, col) mod 8

def coords_to_indices(seq_str):
    """Convert digit string to (row,col) pairs -> rectangle indices"""
    indices = []
    for i in range(0, len(seq_str)-1, 2):
        row = int(seq_str[i]) % 8
        col = int(seq_str[i+1]) % 8
        idx = row * 8 + col
        indices.append(idx)
    return indices

seq1_coords = coords_to_indices("09111819")
seq2_coords = coords_to_indices("11122111")
print(f"  09111819 -> indices: {seq1_coords}")
print(f"  11122111 -> indices: {seq2_coords}")

# =============================================================================
# INTERPRETATION 2: LHIU as multipliers or indices
# =============================================================================
print("\n[2] LHIU interpretations...")
# L=12, H=8, I=9, U=21 (A=1 encoding)
lhiu_a1 = [12, 8, 9, 21]
# L=50, H=?, I=1, U=5 (Roman-ish)
# LHIU could spell something or be hex: 0x4C, 0x48, 0x49, 0x55
lhiu_ascii = [0x4C, 0x48, 0x49, 0x55]  # 76, 72, 73, 85
print(f"  LHIU (A=1): {lhiu_a1}")
print(f"  LHIU (ASCII): {lhiu_ascii}")

# =============================================================================
# INTERPRETATION 3: |-I xN+ as formula
# =============================================================================
print("\n[3] Formula: |-I xN+ LHIU /x? ...")
# |-I = |O - I| = Shell (absolute difference)
# xN+ = multiply by N, add
# /x? = divide by x
# Combined: shell * N / x where N and x come from somewhere

# Try: shell * 12 / 8 (using L and H from LHIU)
areas = get_areas('shell', 17, 6)
for n, x in [(12, 8), (8, 9), (9, 21), (12, 9), (8, 21)]:
    pairs = []
    for i in range(0, 64, 2):
        val = (areas[i] + areas[i+1]) * n // x
        pairs.append(val % 256)
    if check_key(pairs, f"shell_times{n}_div{x}"):
        exit()

# =============================================================================
# INTERPRETATION 4: 09111819 as base-N number
# =============================================================================
print("\n[4] Numbers as encoded values...")
# 09111819 in decimal = 9111819
# 11122111 in decimal = 11122111
num1 = 9111819
num2 = 11122111
print(f"  09111819 = {num1}, binary: {bin(num1)}")
print(f"  11122111 = {num2}, binary: {bin(num2)}")
print(f"  Sum: {num1 + num2}")
print(f"  XOR: {num1 ^ num2}")

# =============================================================================
# INTERPRETATION 5: "FIN" as Fibonacci Index Numbers
# =============================================================================
print("\n[5] FIN = Fibonacci pairing...")
fib = [1, 1, 2, 3, 5, 8, 13, 21, 34, 55]

# Pair rect[i] with rect[i + fib[i % len(fib)]]
for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)
        for start_fib in range(5):
            pairs = []
            for i in range(32):
                idx1 = i * 2
                fib_offset = fib[(i + start_fib) % len(fib)]
                idx2 = (idx1 + fib_offset) % 64
                pairs.append((areas[idx1] + areas[idx2]) % 256)
            if check_key(pairs, f"fib_start{start_fib}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 6: Read digits as individual offsets per pair
# =============================================================================
print("\n[6] Individual digit offsets...")
# 0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1 = 16 digits
# Extend to 32 by repeating
digits = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
digits_ext = (digits * 2)[:32]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        # Offset from consecutive pair
        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                idx1 = i * 2
                offset = digits_ext[i]
                idx2 = (idx1 + 1 + offset) % 64  # +1 for "following", +offset for non-consecutive
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"digit_offset_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 7: 09111819 as row selection pattern
# =============================================================================
print("\n[7] Row selection pattern...")
# Digits tell which row to pick from for each byte
row_pattern = [0,9%8,1,1,1,8%8,1,9%8,1,1,1,2,2,1,1,1]  # = [0,1,1,1,1,0,1,1,1,1,1,2,2,1,1,1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                row1 = row_pattern[i % len(row_pattern)]
                row2 = row_pattern[(i+1) % len(row_pattern)]
                col = i % 8
                idx1 = row1 * 8 + col
                idx2 = row2 * 8 + (col + 1) % 8
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"row_select_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 8: Alternating sequences
# =============================================================================
print("\n[8] Alternating sequences 09111819 and 11122111...")
seq1 = [0,9,1,1,1,8,1,9]
seq2 = [1,1,1,2,2,1,1,1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        # Alternate between seq1 and seq2 for offset
        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                idx1 = i * 2
                if i < 16:
                    offset = seq1[i % 8]
                else:
                    offset = seq2[(i-16) % 8]
                idx2 = (idx1 + offset) % 64
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"alt_seq_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 9: XOR with sequence values
# =============================================================================
print("\n[9] XOR with sequence...")
full_seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1] * 2

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(0, 64, 2):
                val = (areas[i] + areas[i+1]) // div
                xor_val = full_seq[i // 2]
                pairs.append((val ^ xor_val) % 256)
            if check_key(pairs, f"xor_seq_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 10: Matrix coordinates
# =============================================================================
print("\n[10] Matrix coordinate pairing...")
# 09,11,18,19 and 11,12,21,11 as (row,col) pairs
coord_pairs_1 = [(0,9%8), (1,1), (1,8%8), (1,9%8)]  # [(0,1), (1,1), (1,0), (1,1)]
coord_pairs_2 = [(1,1), (1,2), (2,1), (1,1)]

all_coords = coord_pairs_1 + coord_pairs_2  # 8 coordinate pairs

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        # Use coordinates to select rectangles
        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                c1 = all_coords[i % len(all_coords)]
                c2 = all_coords[(i + 1) % len(all_coords)]
                idx1 = c1[0] * 8 + c1[1]
                idx2 = c2[0] * 8 + c2[1]
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"coord_pairs_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 11: "Following" means next in specific sequence
# =============================================================================
print("\n[11] Custom traversal order...")
# Build traversal from the digits
traversal = []
for d in [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]:
    traversal.extend([d % 8, (d+1)%8])  # Each digit and its follower

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                idx1 = traversal[(i*2) % len(traversal)] * 4 + i % 4
                idx2 = traversal[(i*2+1) % len(traversal)] * 4 + (i+1) % 4
                idx1 = idx1 % 64
                idx2 = idx2 % 64
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"traversal_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 12: Sum includes multiplier from sequence
# =============================================================================
print("\n[12] Sequence as multiplier...")
seq_mult = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            for i in range(32):
                idx1 = i * 2
                idx2 = i * 2 + 1
                m = seq_mult[i % len(seq_mult)]
                if m == 0:
                    m = 1
                val = (areas[idx1] * m + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"seq_mult_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 13: Different area types per position based on digit
# =============================================================================
print("\n[13] Mixed area types based on digits...")
# 0 = outer, 1 = inner, 2 = shell, 8 = shell*8, 9 = shell*9
digit_seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1] * 4

def get_mixed_value(rect_idx, digit):
    o, i, s = RECT_DATA[rect_idx]
    if rect_idx == 39:
        s *= 17
    if rect_idx == 52:
        s *= 6
    if digit == 0:
        return o
    elif digit == 1:
        return i
    elif digit == 2:
        return s
    elif digit == 8:
        return s * 8
    elif digit == 9:
        return s + o  # shell + outer?
    else:
        return s

for div in [1, 8, 16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = i * 2 + 1
        d1 = digit_seq[idx1]
        d2 = digit_seq[idx2]
        v1 = get_mixed_value(idx1, d1)
        v2 = get_mixed_value(idx2, d2)
        val = (v1 + v2) // div
        pairs.append(val % 256)
    if check_key(pairs, f"mixed_area_div{div}"):
        exit()

# =============================================================================
# INTERPRETATION 14: Binary representation
# =============================================================================
print("\n[14] Binary interpretation...")
# 09111819 in binary digits of each number: 0,9,1,1,1,8,1,9
# 9 = 1001, 8 = 1000, 1 = 0001
# This could indicate bit patterns

bin_seq1 = [0,1,0,0,1,0,0,0,1,0,0,0,1,1,0,0,0,0,0,0,1,1,0,0,1]  # rough
# Let's just use the raw digits as binary-ish selectors

# =============================================================================
# INTERPRETATION 15: Reverse one sequence
# =============================================================================
print("\n[15] One sequence reversed...")
seq1 = [0,9,1,1,1,8,1,9]
seq2_rev = [1,1,1,2,2,1,1,1][::-1]  # Reversed

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            combined = seq1 + seq2_rev
            for i in range(32):
                idx1 = i * 2
                offset = combined[i % len(combined)]
                idx2 = (idx1 + offset) % 64
                val = (areas[idx1] + areas[idx2]) // div
                pairs.append(val % 256)
            if check_key(pairs, f"seq1_seq2rev_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# INTERPRETATION 16: "FIN" separates two different operations
# =============================================================================
print("\n[16] Two different operations...")
# First 16 bytes use seq1 pattern, last 16 use seq2 pattern differently

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        areas = get_areas('shell', mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            pairs = []
            # First half: sum consecutive
            for i in range(16):
                val = (areas[i*2] + areas[i*2+1]) // div
                pairs.append(val % 256)
            # Second half: subtract
            for i in range(16, 32):
                val = abs(areas[i*2] - areas[i*2+1]) // div
                pairs.append(val % 256)

            if check_key(pairs, f"sum_then_sub_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# FINAL: Brute force offset combinations
# =============================================================================
print("\n[17] Brute force small offset patterns...")
checked = 0
for mult40 in [17]:
    for mult53 in [6]:
        areas = get_areas('shell', mult40, mult53)

        # Try all possible 2-element offset patterns
        for o1 in range(10):
            for o2 in range(10):
                offsets = [o1, o2] * 16
                for div in [8, 16, 32, 64]:
                    pairs = []
                    for i in range(32):
                        idx1 = i * 2
                        offset = offsets[i]
                        idx2 = (idx1 + offset) % 64
                        val = (areas[idx1] + areas[idx2]) // div
                        pairs.append(val % 256)
                    if check_key(pairs, f"bf_o{o1}_{o2}_div{div}"):
                        exit()
                    checked += 1

print(f"\nChecked {checked} additional combinations")
print("Mini-puzzle still not cracked.")
print("\nPossible remaining interpretations:")
print("  - The symbols form a more complex formula")
print("  - There's steganography in the image we're missing")
print("  - The coordinates map to specific pixel positions")
