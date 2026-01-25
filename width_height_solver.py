"""
Try using WIDTH and HEIGHT of rectangles instead of areas.
The mini-puzzle might encode which dimension to use.
"""
import hashlib
import ecdsa
import base58

# From the image extraction (partial - 54 found)
# But let's use the original dataset which has all 64

# Original areas were Outer, Inner, Shell
# Let me approximate widths/heights using sqrt

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
        print(f"SOLVED! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"{'='*60}")
        return True
    return False

import math

# Get approximate dimensions from areas
def get_approx_dims():
    """Estimate width/height from area using sqrt and aspect hints"""
    dims = []
    for i, (o, inner, s) in enumerate(RECT_DATA):
        # Use outer area
        sqrt_o = int(math.sqrt(o))
        # Shell dimensions (approximation)
        sqrt_s = int(math.sqrt(s)) if s > 0 else 0
        dims.append((sqrt_o, sqrt_s, o, s))
    return dims

# Mini-puzzle: 09111819 FIN 11122111
# |-I  = |Outer - Inner| = Shell
# xN+ = multiply N, add
# LHIU = ?
# /x? = divide

# New interpretation:
# 0,9,1,1,1,8,1,9 could mean: W(0), H(9%2=1), W, W, W, H(8%2=0)=W, W, H
# Where 0=Width, 1=Height, odd=H, even=W

print("="*70)
print("WIDTH/HEIGHT INTERPRETATION")
print("="*70)

# Interpretation: digits mod 2 tell us whether to use W or H
# 0=W, 1=H, 2=W, 8=W, 9=H
seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
wh_select = [d % 2 for d in seq]  # 0=W, 1=H
print(f"Digit sequence: {seq}")
print(f"W/H selection (d%2): {wh_select}")  # [0,1,1,1,1,0,1,1,1,1,1,0,0,1,1,1]

dims = get_approx_dims()

# Apply selection
for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_areas = [r[2] for r in RECT_DATA]
        shell_areas[39] *= mult40
        shell_areas[52] *= mult53

        sqrts = [int(math.sqrt(s)) for s in shell_areas]

        # Create values based on W/H selection extended to 64
        wh_ext = (wh_select * 4)[:64]

        for div in [1, 2, 4, 8]:
            pairs = []
            for i in range(32):
                idx1, idx2 = i * 2, i * 2 + 1
                # Use sqrt for "dimension", w/h selection for modification
                v1 = sqrts[idx1] if wh_ext[idx1] == 0 else shell_areas[idx1]
                v2 = sqrts[idx2] if wh_ext[idx2] == 0 else shell_areas[idx2]
                val = (v1 + v2) // div
                pairs.append(val % 256)

            if check_key(pairs, f"wh_select_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# Try using the perimeter instead of area
# =============================================================================
print("\n[2] Using perimeter (2W + 2H = 4*sqrt(A) approx)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_areas = [r[2] for r in RECT_DATA]
        shell_areas[39] *= mult40
        shell_areas[52] *= mult53

        # Approximate perimeter
        perimeters = [4 * int(math.sqrt(s)) for s in shell_areas]

        for div in [1, 2, 4, 8, 16]:
            pairs = []
            for i in range(0, 64, 2):
                val = (perimeters[i] + perimeters[i+1]) // div
                pairs.append(val % 256)

            if check_key(pairs, f"perimeter_div{div}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# LHIU interpretation: L=sum, H=diff, I=inner, U=union?
# =============================================================================
print("\n[3] LHIU as operations...")
# L = Lower dimension, H = Higher dimension, I = Inner, U = ?

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer = [r[0] for r in RECT_DATA]
        inner = [r[1] for r in RECT_DATA]
        shell = [r[2] for r in RECT_DATA]
        shell[39] *= mult40
        shell[52] *= mult53

        # Try: L=12, H=8, I=9, U=21 as modular divisors
        for L, H, I, U in [(12, 8, 9, 21), (21, 12, 9, 8), (8, 9, 12, 21)]:
            pairs = []
            for i in range(32):
                idx1, idx2 = i * 2, i * 2 + 1
                # Apply different operations based on position mod 4
                pos = i % 4
                if pos == 0:
                    val = (shell[idx1] + shell[idx2]) // L
                elif pos == 1:
                    val = (shell[idx1] + shell[idx2]) // H
                elif pos == 2:
                    val = (inner[idx1] + inner[idx2]) // I
                else:
                    val = (outer[idx1] + outer[idx2]) // U
                pairs.append(val % 256)

            if check_key(pairs, f"LHIU_{L}_{H}_{I}_{U}_m{mult40}_{mult53}"):
                exit()

# =============================================================================
# Final: Try single-byte extraction from each rectangle
# =============================================================================
print("\n[4] Single byte per two rectangles using various formulas...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = [r[2] for r in RECT_DATA]
        shell[39] *= mult40
        shell[52] *= mult53

        # Formula: (a + b) / 64 is the most likely based on hint
        # But maybe with offsets from the sequence
        seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

        for base_div in [32, 64, 128]:
            # Add sequence value to result
            pairs = []
            for i in range(32):
                idx1, idx2 = i * 2, i * 2 + 1
                s = seq[i % len(seq)]
                val = (shell[idx1] + shell[idx2] + s) // base_div
                pairs.append(val % 256)

            if check_key(pairs, f"add_seq_div{base_div}_m{mult40}_{mult53}"):
                exit()

            # Multiply by sequence value
            pairs = []
            for i in range(32):
                idx1, idx2 = i * 2, i * 2 + 1
                s = seq[i % len(seq)]
                if s == 0:
                    s = 1
                val = (shell[idx1] + shell[idx2]) * s // base_div
                pairs.append(val % 256)

            if check_key(pairs, f"mult_seq_div{base_div}_m{mult40}_{mult53}"):
                exit()

print("\nNo solution found yet.")
print("\nThe mini-puzzle encoding remains a mystery.")
print("Key insight needed: how '09111819 FIN 11122111' maps to pairing/formula")
