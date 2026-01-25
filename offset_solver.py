"""
Mini-puzzle as OFFSET pattern for pairing:
09111819 FIN 11122111 = offsets [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

Each digit tells us how far to skip from the "expected" consecutive pair.
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
KNOWN_BYTE = 119

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
    if len(byte_list) != 32 or KNOWN_BYTE not in byte_list:
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

shell = [r[2] for r in RECT_DATA]
shell[39] *= 17
shell[52] *= 6

offsets = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
offsets_32 = (offsets * 2)[:32]

print("="*70)
print("OFFSET-BASED PAIRING")
print("="*70)
print(f"Offsets: {offsets}")
print(f"Extended to 32: {offsets_32}")
print()

# ============================================================================
# Interpretation 1: offset from consecutive position
# ============================================================================
print("\n[1] Offset from consecutive: pair[i] = rect[2i] + rect[2i+1+offset[i]]")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = (i * 2 + 1 + offsets_32[i]) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: {pairs}")
    print(f"    Contains 119: {119 in pairs}")
    if check_key(pairs, f"offset_consec_div{div}"):
        exit()

# ============================================================================
# Interpretation 2: offset determines second rectangle
# ============================================================================
print("\n[2] Offset determines second: pair[i] = rect[2i] + rect[offset[i] * 2]")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = (offsets_32[i] * 2) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"offset_second_div{div}"):
        exit()

# ============================================================================
# Interpretation 3: offset as skip in column-major order
# ============================================================================
print("\n[3] Column-major with offsets")

col_major = []
for col in range(8):
    for row in range(8):
        col_major.append(row * 8 + col)

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = col_major[i * 2]
        offset = offsets_32[i]
        idx2 = col_major[(i * 2 + 1 + offset) % 64]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"colmajor_offset_div{div}"):
        exit()

# ============================================================================
# Interpretation 4: Split sequences - first 16 use seq1, second 16 use seq2
# ============================================================================
print("\n[4] Split: first half seq1 offsets, second half seq2 offsets")

seq1 = [0,9,1,1,1,8,1,9]
seq2 = [1,1,1,2,2,1,1,1]

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        if i < 16:
            offset = seq1[i % 8]
        else:
            offset = seq2[(i - 16) % 8]
        idx2 = (idx1 + 1 + offset) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"split_seq_div{div}"):
        exit()

# ============================================================================
# Interpretation 5: Digits select rectangle from specific rows
# ============================================================================
print("\n[5] Digit selects row")

# Digit 0 = row 0, digit 9 = row 1 (9%8), digit 1 = row 1, etc.
row_sel = [d % 8 for d in offsets]
print(f"Row selection pattern: {row_sel}")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        row1 = row_sel[i % len(row_sel)]
        row2 = row_sel[(i + 1) % len(row_sel)]
        col = i % 8
        idx1 = row1 * 8 + col
        idx2 = row2 * 8 + (col + 1) % 8
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"row_select_div{div}"):
        exit()

# ============================================================================
# Interpretation 6: Following (not consecutive) = next non-zero offset
# ============================================================================
print("\n[6] 'Following' = skip to next based on offset")

# Build index sequence where each step skips by offset amount
indices = []
current = 0
for i in range(64):
    indices.append(current % 64)
    current += offsets_32[i % 32] + 1  # +1 for "following"

print(f"Index sequence (first 20): {indices[:20]}")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = indices[i * 2 % len(indices)]
        idx2 = indices[(i * 2 + 1) % len(indices)]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"following_skip_div{div}"):
        exit()

# ============================================================================
# Interpretation 7: Cumulative offsets
# ============================================================================
print("\n[7] Cumulative offsets")

cumulative = []
total = 0
for o in offsets_32:
    total += o
    cumulative.append(total % 64)

print(f"Cumulative offsets: {cumulative}")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = cumulative[i]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"cumulative_div{div}"):
        exit()

# ============================================================================
# Interpretation 8: Two-digit pairs as indices
# ============================================================================
print("\n[8] Two-digit pairs as (row, col)")

# 09 = (0,9%8) = (0,1), 11 = (1,1), 18 = (1,8%8) = (1,0), etc.
digit_pairs = [(0,1), (1,1), (1,0), (1,1), (1,1), (1,2), (2,1), (1,1)]
print(f"Digit pairs: {digit_pairs}")

for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(32):
        dp = digit_pairs[i % len(digit_pairs)]
        idx1 = dp[0] * 8 + (i % 8)
        idx2 = dp[1] * 8 + ((i + 1) % 8)
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"digit_pairs_div{div}"):
        exit()

# ============================================================================
# Interpretation 9: FIN = Final transformation
# ============================================================================
print("\n[9] FIN as 'final' transformation marker")

# Apply seq1, then transform, then seq2
for div in [16, 32, 64, 128]:
    pairs = []
    for i in range(16):
        idx1 = i * 2
        offset = seq1[i % 8]
        idx2 = (idx1 + 1 + offset) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    # "FIN" = reverse for second half
    for i in range(16, 32):
        idx1 = (31 - (i - 16)) * 2  # Reverse order
        offset = seq2[(i - 16) % 8]
        idx2 = (idx1 + 1 + offset) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"fin_reverse_div{div}"):
        exit()

# ============================================================================
# Interpretation 10: Absolute indices from sequences
# ============================================================================
print("\n[10] Sequences as absolute rectangle indices")

# Treat 09111819 11122111 as pairs of indices: (0,9), (11,18), (19,11), etc.
# Or: 09, 11, 18, 19, 11, 12, 21, 11 as individual indices
abs_indices = [9, 11, 18, 19, 11, 12, 21, 11]  # From "09111819" and "11122111"

for div in [8, 16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1 = abs_indices[i % len(abs_indices)]
        idx2 = abs_indices[(i + 1) % len(abs_indices)]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    print(f"  Div {div}: Contains 119: {119 in pairs}")
    if check_key(pairs, f"abs_indices_div{div}"):
        exit()

print("\nNo solution found with offset interpretations.")
print("\nThe mini-puzzle may require a completely different interpretation.")
