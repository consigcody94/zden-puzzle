"""
Focus on divisor 7 and the relationship 17 * 7 = 119
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
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

print("="*70)
print("DIVISOR 7 AND 119 EXPLORATION")
print("="*70)

# ============================================================================
# Divisor 7 with various multipliers
# ============================================================================
print("\n[1] Using divisor 7...")

for mult40 in [1, 17]:
    for mult53 in [1, 6, 7]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for base in [1, 8, 16, 32]:
            div = 7 * base
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                print(f"  m{mult40}_{mult53} div{div}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"div7_m{mult40}_{mult53}_base{base}"):
                    exit()

# ============================================================================
# Multiply by 17, divide by 119
# ============================================================================
print("\n[2] Multiply by 17, mod/div by 119...")

for mult40 in [1, 17]:
    for mult53 in [1, 6, 7]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # (sum * 17) % 119
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 17) % 119 for i in range(32)]
        if check_key(pairs, f"times17_mod119_m{mult40}_{mult53}"):
            exit()

        # (sum * 17) // 119
        for scale in [1, 10, 100]:
            pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 17) // (119 * scale) % 256 for i in range(32)]
            if check_key(pairs, f"times17_div119_scale{scale}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Use 119 as XOR constant
# ============================================================================
print("\n[3] XOR with 119...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64, 128]:
            pairs = [((shell_m[i*2] + shell_m[i*2+1]) // div) ^ 119 for i in range(32)]
            pairs = [p % 256 for p in pairs]
            if check_key(pairs, f"xor119_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Use 7 as shift
# ============================================================================
print("\n[4] Bit shift by 7...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        pairs = [((shell_m[i*2] + shell_m[i*2+1]) >> 7) % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  Shift 7 m{mult40}_{mult53}: Contains 119")
            if check_key(pairs, f"shift7_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Modulo 119
# ============================================================================
print("\n[5] Modulo 119...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) % 119 for i in range(32)]
        if check_key(pairs, f"mod119_m{mult40}_{mult53}"):
            exit()

        # Double mod: first reduce, then mod 256
        for first_mod in [119, 7, 17]:
            pairs = [((shell_m[i*2] + shell_m[i*2+1]) % first_mod) for i in range(32)]
            # Pad to valid bytes
            pairs = [(p + 100) % 256 if p < 100 else p for p in pairs]
            if check_key(pairs, f"mod{first_mod}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Combined 17*7 operations
# ============================================================================
print("\n[6] Combined 17*7 operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # (sum * 7) // 17
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 7) // 17 % 256 for i in range(32)]
        if check_key(pairs, f"times7_div17_m{mult40}_{mult53}"):
            exit()

        # (sum // 7) * 17
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 7 * 17) % 256 for i in range(32)]
        if check_key(pairs, f"div7_times17_m{mult40}_{mult53}"):
            exit()

        # ((sum // 17) + 7)
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 17 + 7) % 256 for i in range(32)]
        if check_key(pairs, f"div17_plus7_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# LHIU with 7
# ============================================================================
print("\n[7] LHIU (12,8,9,21) combined with 7...")

L, H, I, U = 12, 8, 9, 21

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

for mult in [L, H, I, U]:
    for div in [7, 7*8, 7*16, 119]:
        if div == 0:
            continue
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) * mult) // div % 256 for i in range(32)]
        if check_key(pairs, f"lhiu_{mult}_div{div}"):
            exit()

# ============================================================================
# Position 26 (where rect 53 pair is)
# ============================================================================
print("\n[8] Force byte 26 to be 119...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

# Find what divisor makes pair 26 = 119
sum_26 = shell_m[52] + shell_m[53]  # After mult: 118*6 + 88 = 708 + 88 = 796
print(f"  Sum at pair 26 (with 6x): {sum_26}")

# For 796 / d = 119 => d = 6.69
# Not clean. Try without multiplier on 53
sum_26_no_mult = shell[52] + shell[53]  # 118 + 88 = 206
print(f"  Sum at pair 26 (no mult): {sum_26_no_mult}")

# For 206 to become 119: 206 - 87 = 119, or 206 // 1.73
# Not clean either

# What if we need to add rects in different order?
# Pair 26 normally = rect[52] + rect[53]
# What if it should be rect[52] + something_else?

print("\nDivisor 7 exploration complete.")
print("\nKey insight: 17 * 7 = 119, and rect40_shell / rect53_shell = 7")
