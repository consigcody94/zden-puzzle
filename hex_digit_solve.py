"""
NEW APPROACH: Rectangles encode HEX DIGITS, not byte values!
Two hex digits combine as: D1*16 + D2 (not D1 + D2)

Each rectangle should evaluate to 0-15 (hex digit)
Two consecutive/following rectangles form one byte
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
            return True
    return False

print("="*70)
print("HEX DIGIT APPROACH")
print("="*70)
print("Each rectangle -> hex digit (0-15)")
print("Two hex digits -> one byte: D1*16 + D2")
print()

# ============================================================================
# Convert each rectangle area to hex digit (0-15)
# ============================================================================
print("[1] Shell areas to hex digits...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Various ways to convert area to hex digit
        for divisor in [16, 32, 64, 100, 128, 256, 500]:
            # Method 1: area / divisor % 16
            hex_digits = [s // divisor % 16 for s in shell_m]
            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                print(f"  div{divisor} m{mult40}_{mult53}: 0x77 at {[i for i,v in enumerate(pairs) if v==0x77]}")
                if check_key(pairs, f"hex_div{divisor}_m{mult40}_{mult53}"):
                    exit()

        # Method 2: area % 16 directly
        hex_digits = [s % 16 for s in shell_m]
        pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
        if 0x77 in pairs:
            print(f"  mod16 m{mult40}_{mult53}: 0x77 at {[i for i,v in enumerate(pairs) if v==0x77]}")
            if check_key(pairs, f"hex_mod16_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Try with LXIV = 64 as the key divisor for hex conversion
# ============================================================================
print("\n[2] Using 64 (LXIV) for hex digit extraction...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # area / 64 % 16
        hex_digits = [s // 64 % 16 for s in shell_m]
        pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
        print(f"  div64 mod16 m{mult40}_{mult53}: {[hex(p) for p in pairs[:8]]}...")
        if 0x77 in pairs:
            print(f"    Contains 0x77 at {[i for i,v in enumerate(pairs) if v==0x77]}")
            if check_key(pairs, f"hex_div64_mod16_m{mult40}_{mult53}"):
                exit()

        # (area + offset) / 64 % 16
        for offset in [0, 32, 64]:
            hex_digits = [(s + offset) // 64 % 16 for s in shell_m]
            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                if check_key(pairs, f"hex_off{offset}_div64_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# What if hex digit is determined by area ratios?
# ============================================================================
print("\n[3] Ratio-based hex digits...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer_m = outer.copy()
        inner_m = inner.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        # Ratio of outer to inner as hex digit
        hex_digits = []
        for i in range(64):
            if inner_m[i] > 0:
                ratio = outer_m[i] * 16 // inner_m[i]
                hex_digits.append(ratio % 16)
            else:
                hex_digits.append(0)

        pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
        if 0x77 in pairs:
            print(f"  Ratio m{mult40}_{mult53}: 0x77 at {[i for i,v in enumerate(pairs) if v==0x77]}")
            if check_key(pairs, f"hex_ratio_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# What if the 17 and 6 pixel lines indicate which bit position?
# ============================================================================
print("\n[4] Bit position interpretation of 17 and 6...")

# 17 in binary = 10001, 6 in binary = 110
# Maybe these indicate specific bits to set or extract

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [64, 128]:
            # Extract specific bits
            hex_digits = []
            for i, s in enumerate(shell_m):
                # Use different bit extraction based on position
                if i == 39:
                    val = (s >> 4) & 0xF  # Bits 4-7
                elif i == 52:
                    val = (s >> 2) & 0xF  # Bits 2-5
                else:
                    val = (s // div) % 16
                hex_digits.append(val)

            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                if check_key(pairs, f"bitpos_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# 0x77 = 7*16 + 7, so we need two rectangles that both give 7
# ============================================================================
print("\n[5] Looking for natural 7s...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [16, 32, 64, 100, 119, 128]:
            hex_digits = [s // div % 16 for s in shell_m]

            # Find pairs of 7s
            sevens = [i for i, d in enumerate(hex_digits) if d == 7]
            if len(sevens) >= 2:
                print(f"  div{div} m{mult40}_{mult53}: 7s at positions {sevens}")

            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                pos = [i for i, v in enumerate(pairs) if v == 0x77]
                print(f"    -> 0x77 at byte {pos}")
                if check_key(pairs, f"hex_7s_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Non-consecutive pairing with hex digit combination
# ============================================================================
print("\n[6] Non-consecutive hex digit pairing...")

# Try skip patterns
for skip in [2, 8, 9, 32]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            for div in [64, 100, 128]:
                hex_digits = [s // div % 16 for s in shell_m]

                # Pair with skip
                pairs = []
                for i in range(32):
                    d1 = hex_digits[i]
                    d2 = hex_digits[(i + skip) % 64]
                    pairs.append(d1 * 16 + d2)

                if 0x77 in pairs:
                    if check_key(pairs, f"hex_skip{skip}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Using Outer areas instead of Shell
# ============================================================================
print("\n[7] Outer areas to hex digits...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer_m = outer.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53

        for div in [256, 500, 1000]:
            hex_digits = [o // div % 16 for o in outer_m]
            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                print(f"  Outer div{div} m{mult40}_{mult53}: 0x77 found")
                if check_key(pairs, f"hex_outer_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Using Inner areas
# ============================================================================
print("\n[8] Inner areas to hex digits...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        inner_m = inner.copy()
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for div in [128, 256, 500]:
            hex_digits = [i_val // div % 16 for i_val in inner_m]
            pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]
            if 0x77 in pairs:
                print(f"  Inner div{div} m{mult40}_{mult53}: 0x77 found")
                if check_key(pairs, f"hex_inner_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Normalized to 0-15 range using min-max
# ============================================================================
print("\n[9] Min-max normalization to 0-15...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        min_s = min(shell_m)
        max_s = max(shell_m)
        range_s = max_s - min_s if max_s > min_s else 1

        hex_digits = [int((s - min_s) / range_s * 15) for s in shell_m]
        pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]

        print(f"  MinMax m{mult40}_{mult53}: {[hex(p) for p in pairs[:8]]}...")
        if 0x77 in pairs:
            if check_key(pairs, f"hex_minmax_m{mult40}_{mult53}"):
                exit()

print("\nHex digit approach complete.")
