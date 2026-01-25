"""
Decode the mini-puzzle: 09111819 FIN 11122111
And the corner symbols: |-I, xN+, LHIU, /x?
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
KNOWN_BYTE = 0x77

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
        print(f"FOUND! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"Bytes: {byte_list}")
        print(f"Addr-C: {addr_c}")
        print(f"Addr-U: {addr_u}")
        print(f"{'='*60}")
        return True
    return False

def get_shell_areas(mult40=17, mult53=6):
    areas = [r[2] for r in RECT_DATA]  # Shell = O - I
    areas[39] *= mult40  # Rect #40
    areas[52] *= mult53  # Rect #53
    return areas

# Mini-puzzle interpretations
print("="*60)
print("MINI-PUZZLE ANALYSIS")
print("="*60)
print()
print("Clues:")
print("  09111819 FIN 11122111")
print("  |-I    (Outer - Inner = Shell?)")
print("  xN+    (multiply by N, add?)")
print("  LHIU   (unknown)")
print("  /x?    (divide by x?)")
print()

# Interpretation 1: 09111819 as offsets for pairing
# Pair rect[i] with rect[i + offset[i % 8]]
offsets1 = [0, 9, 1, 1, 1, 8, 1, 9]
offsets2 = [1, 1, 1, 2, 2, 1, 1, 1]

print("Testing offset-based pairing...")
areas = get_shell_areas()

for off_name, offsets in [("seq1", offsets1), ("seq2", offsets2), ("combined", offsets1+offsets2)]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        offset = offsets[i % len(offsets)]
        idx2 = (idx1 + offset) % 64
        pairs.append((areas[idx1] + areas[idx2]) % 256)

    if check_key(pairs, f"offset_{off_name}"):
        exit()

# Interpretation 2: 09111819 11122111 as two-digit column selectors
# 09, 11, 18, 19, 11, 12, 21, 11
col_pairs = [(0,9), (1,1), (1,8), (1,9), (1,1), (1,2), (2,1), (1,1)]
print(f"\nColumn pairs interpretation: {col_pairs}")

# Interpretation 3: LHIU = Letter to number (L=12, H=8, I=9, U=21)
lhiu_vals = {'L': 12, 'H': 8, 'I': 9, 'U': 21}
print(f"\nLHIU as numbers: {lhiu_vals}")

# Interpretation 4: 09111819 could be dates
# Sept 11, 1819 or Nov 18, 19 or Jan 11, 1819
print("\nDate interpretations:")
print("  09/11/1819 or 11/18/19 or 01/11/1819")

# Interpretation 5: FIN = Finish or Final or Formula INversion
# Maybe reverse the order for the second part?
print("\nFIN interpretation: Apply offsets2 in reverse?")

offsets_rev = offsets2[::-1]
pairs = []
for i in range(32):
    idx1 = i * 2
    if i < 16:
        offset = offsets1[i % len(offsets1)]
    else:
        offset = offsets_rev[(i-16) % len(offsets_rev)]
    idx2 = (idx1 + offset) % 64
    pairs.append((areas[idx1] + areas[idx2]) % 256)

if check_key(pairs, "seq1_then_seq2_reversed"):
    exit()

# Interpretation 6: Digits select which measurement type to use per rectangle
# 0=outer, 1=inner, 2=shell, 8=?, 9=?
print("\nDigit-as-measurement-type interpretation...")
full_digits = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1] * 4  # Repeat for 64 rectangles

mixed_areas = []
for i in range(64):
    d = full_digits[i % len(full_digits)]
    if d == 0:
        mixed_areas.append(RECT_DATA[i][0])  # Outer
    elif d == 1:
        mixed_areas.append(RECT_DATA[i][1])  # Inner
    elif d == 2:
        mixed_areas.append(RECT_DATA[i][2])  # Shell
    elif d == 8:
        mixed_areas.append(RECT_DATA[i][2] * 8)  # Shell * 8?
    elif d == 9:
        mixed_areas.append(RECT_DATA[i][2] * 9)  # Shell * 9?
    else:
        mixed_areas.append(RECT_DATA[i][2])

# Apply multipliers
mixed_areas[39] *= 17
mixed_areas[52] *= 6

for divisor in [1, 8, 16, 32, 64]:
    pairs = []
    for i in range(0, 64, 2):
        pairs.append(((mixed_areas[i] + mixed_areas[i+1]) // divisor) % 256)

    if check_key(pairs, f"mixed_meas_div{divisor}"):
        exit()

# Interpretation 7: The formula -1*x+64/x/
# Could mean: for each value, compute floor((64-x)/x) or abs(-x+64)
print("\nTesting formula interpretations...")
areas = get_shell_areas()

for divisor in [8, 16, 32, 64]:
    pairs_raw = []
    for i in range(0, 64, 2):
        pairs_raw.append(areas[i] + areas[i+1])

    # Formula: (-1 * x + 64) / divisor
    pairs = [abs(-x + 64) // divisor % 256 for x in pairs_raw]
    if check_key(pairs, f"formula_neg_x_plus_64_div{divisor}"):
        exit()

    # Formula: 64 / (x / divisor)
    pairs = [int(64 / (x / divisor)) % 256 if x > 0 else 0 for x in pairs_raw]
    if check_key(pairs, f"formula_64_div_x_div{divisor}"):
        exit()

# Interpretation 8: Using both hint lines
# "consecutive" struck through + "following" = pair non-adjacent but in order
# Maybe pair 1st with 3rd, 2nd with 4th, etc. (skip=2)
print("\nTesting skip patterns with known byte check...")

for skip in range(1, 33):
    pairs = []
    for i in range(32):
        idx1 = i
        idx2 = (i + skip) % 64
        if idx1 == idx2:
            idx2 = (idx1 + 1) % 64
        pairs.append((areas[idx1] + areas[idx2 + 32 if idx2 < 32 else idx2 - 32]) % 256)

    if check_key(pairs, f"skip{skip}_half_offset"):
        exit()

# Interpretation 9: 64 rectangles in spiral or zigzag order
print("\nTesting zigzag reading order...")

def zigzag_indices():
    """Generate zigzag traversal of 8x8 grid"""
    indices = []
    for row in range(8):
        if row % 2 == 0:
            indices.extend(range(row*8, (row+1)*8))
        else:
            indices.extend(range((row+1)*8-1, row*8-1, -1))
    return indices

zigzag = zigzag_indices()
areas_zigzag = [areas[i] for i in zigzag]

for divisor in [1, 8, 16, 32, 64]:
    pairs = []
    for i in range(0, 64, 2):
        pairs.append(((areas_zigzag[i] + areas_zigzag[i+1]) // divisor) % 256)

    if check_key(pairs, f"zigzag_div{divisor}"):
        exit()

print("\nNo match found with current interpretations.")
print("\nKey candidates that produce 0x77:")
print("  - rect[39] + rect[44] with shell*17 = 14711 -> 119")
print("  - This suggests pairing #40 with #45")
print("\nNeed to find the correct pairing pattern that:")
print("  1. Pairs rect 39 with rect 44 at some position")
print("  2. Uses the mini-puzzle encoding correctly")
