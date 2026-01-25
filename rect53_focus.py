"""
Focus on rectangle #53 (shell=118, close to 119)
and its relationship to the solution
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

shell = [r[2] for r in RECT_DATA]

print("="*70)
print("RECTANGLE #53 FOCUS")
print("="*70)

# Key observations:
# - Rect #53 (index 52): shell = 118 = 0x76, one less than 0x77
# - Rect #54 (index 53): shell = 88
# - Rect #40 (index 39): shell = 839
# - Special lines: #40 has 17px, #53 has 6px

print(f"\nRect #53 (idx 52): O={RECT_DATA[52][0]}, I={RECT_DATA[52][1]}, S={RECT_DATA[52][2]}")
print(f"Rect #54 (idx 53): O={RECT_DATA[53][0]}, I={RECT_DATA[53][1]}, S={RECT_DATA[53][2]}")
print(f"Rect #40 (idx 39): O={RECT_DATA[39][0]}, I={RECT_DATA[39][1]}, S={RECT_DATA[39][2]}")

# 118 + 1 = 119
# Maybe the 6-pixel line means "add 1" (or add something)?
# Or maybe 118 * 6 = 708, and 708 / something = 119?

print(f"\n118 + 1 = {118 + 1}")
print(f"118 * 6 = {118 * 6}")
print(f"708 / 6 = {708 / 6}")  # = 118, back to original

# What if the multiplier 6 should be 7 to give 119?
print(f"118 + 6 = {118 + 6}")  # = 124
print(f"17 * 7 = {17 * 7}")  # = 119!

print("\n*** 17 * 7 = 119! ***")
print("Maybe the '6' in the puzzle is actually a hint about 7 (6+1)?")

# ============================================================================
# Try: rect #40 multiplier = 7 (not 17)
# ============================================================================
print("\n[1] Using multiplier 7 for rect #40...")

for mult40 in [7, 77, 119]:
    shell_test = shell.copy()
    shell_test[39] *= mult40

    for div in [16, 32, 64]:
        pairs = [(shell_test[i*2] + shell_test[i*2+1]) // div % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  mult40={mult40}, div{div}: Contains 119")
            if check_key(pairs, f"mult{mult40}_div{div}"):
                exit()

# ============================================================================
# Try: rect #53 value becomes 119 directly
# ============================================================================
print("\n[2] Rect #53 shell becomes 119...")

shell_119 = shell.copy()
shell_119[52] = 119  # Force to 119

for div in [1, 8, 16, 32, 64]:
    pairs = [(shell_119[i*2] + shell_119[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Forced 119, div{div}: Contains 119 at {[i for i,v in enumerate(pairs) if v==119]}")
        if check_key(pairs, f"forced119_div{div}"):
            exit()

# ============================================================================
# Try: Position of 119 is at byte index 26 (rect 52/2 = 26)
# ============================================================================
print("\n[3] Byte position analysis...")

# Rect 52 is in pair 26 (52 // 2)
# Maybe byte 26 should be 119?

for div in [32, 64, 128]:
    pairs = [(shell[i*2] + shell[i*2+1]) // div % 256 for i in range(32)]
    print(f"  Div {div}: byte[26] = {pairs[26]}")

    # What divisor would make pair 26 equal to 119?
    sum_26 = shell[52] + shell[53]  # 118 + 88 = 206
    print(f"    Sum at pair 26: {sum_26}")
    # 206 / x = 119 => x = 206/119 = 1.73...
    # 206 % 256 = 206, not 119
    # Need sum to give 119 after some operation

# ============================================================================
# What sums naturally give 119?
# ============================================================================
print("\n[4] Finding pairs that naturally sum to ~119...")

for i in range(32):
    pair_sum = shell[i*2] + shell[i*2+1]
    # What div would give 119?
    if pair_sum >= 119:
        needed_div = pair_sum // 119
        actual = (pair_sum // needed_div) % 256
        if actual == 119:
            print(f"  Pair {i}: sum={pair_sum}, div={needed_div} gives 119")

# ============================================================================
# Maybe use Outer - Inner for rect 53 differently
# ============================================================================
print("\n[5] Different calculation for special rects...")

# Rect 53: O=126, I=8, S=118
# What if we use O=126 directly, and 126 - 7 = 119?
print(f"  Rect #53: Outer = {RECT_DATA[52][0]}")
print(f"  126 - 7 = {126 - 7}")  # = 119!

# Try using Outer - 7 for rect 53
shell_o7 = shell.copy()
shell_o7[52] = RECT_DATA[52][0] - 7  # 126 - 7 = 119

for div in [1, 8, 16, 32, 64]:
    pairs = [(shell_o7[i*2] + shell_o7[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  O-7 method, div{div}: Contains 119")
        if check_key(pairs, f"o_minus_7_div{div}"):
            exit()

# ============================================================================
# What if BOTH special rects contribute to 119?
# ============================================================================
print("\n[6] Combination of special rects...")

# Rect 39 shell = 839
# Rect 52 shell = 118
# 839 + 118 = 957... not directly useful
# 839 - 118 = 721
# 839 * 118 = 99002
# 839 % 118 = 13
# 839 // 118 = 7  # !!!
print(f"  839 // 118 = {839 // 118}")  # = 7, and 17 * 7 = 119!

# Maybe divisor is derived from relationship between special rects?
special_div = shell[39] // shell[52]  # = 7
print(f"  Special divisor (839/118): {special_div}")

# Using special_div in calculations
for base_div in [1, 8, 16]:
    combined_div = special_div * base_div
    if combined_div > 0:
        pairs = [(shell[i*2] + shell[i*2+1]) // combined_div % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  Special div * {base_div} = {combined_div}: Contains 119")
            if check_key(pairs, f"special_div_x{base_div}"):
                exit()

# ============================================================================
# 17 * 7 = 119, and special rects are #40 (17px) and #53 (6+1=7?)
# ============================================================================
print("\n[7] Using 17*7=119 relationship...")

# Apply: rect #40 gets multiplied by 17, rect #53 gets multiplied by 7
shell_17_7 = shell.copy()
shell_17_7[39] *= 17
shell_17_7[52] *= 7  # Not 6, but 7

for div in [16, 32, 64, 128]:
    pairs = [(shell_17_7[i*2] + shell_17_7[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  17/7 multipliers, div{div}: Contains 119 at {[i for i,v in enumerate(pairs) if v==119]}")
        if check_key(pairs, f"m17_7_div{div}"):
            exit()

# Also try 17 and 1 (118 + 1 = 119)
shell_17_1 = shell.copy()
shell_17_1[39] *= 17
shell_17_1[52] += 1  # Add 1 to make it 119

for div in [1, 8, 16, 32, 64]:
    pairs = [(shell_17_1[i*2] + shell_17_1[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  17/+1, div{div}: Contains 119")
        if check_key(pairs, f"m17_plus1_div{div}"):
            exit()

print("\nRect #53 focus complete.")
print("\nKey relationship discovered: 839 // 118 = 7, and 17 * 7 = 119")
