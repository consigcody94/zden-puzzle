"""
Try alternative key formats and derivation methods
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
print("ALTERNATIVE FORMAT EXPLORATION")
print("="*70)

# ============================================================================
# Test 1: SHA256 of raw data
# ============================================================================
print("\n[1] SHA256 of various data representations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # SHA256 of shell bytes (little endian)
        data = b''.join(s.to_bytes(2, 'little') for s in shell_m)
        h = hashlib.sha256(data).digest()
        if check_key(list(h), f"sha256_le_m{mult40}_{mult53}"):
            exit()

        # SHA256 of shell bytes (big endian)
        data = b''.join(s.to_bytes(2, 'big') for s in shell_m)
        h = hashlib.sha256(data).digest()
        if check_key(list(h), f"sha256_be_m{mult40}_{mult53}"):
            exit()

        # Double SHA256
        data = b''.join(s.to_bytes(2, 'little') for s in shell_m)
        h = hashlib.sha256(hashlib.sha256(data).digest()).digest()
        if check_key(list(h), f"dsha256_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Test 2: Different byte orderings
# ============================================================================
print("\n[2] Different byte orderings...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Reverse
            if check_key(base[::-1], f"reverse_div{div}_m{mult40}_{mult53}"):
                exit()

            # Byte swap pairs
            swapped = []
            for i in range(0, 32, 2):
                swapped.append(base[i+1] if i+1 < 32 else base[i])
                swapped.append(base[i])
            if check_key(swapped, f"swap_pairs_div{div}_m{mult40}_{mult53}"):
                exit()

            # Nibble swap
            nibble_swap = [((b & 0x0F) << 4) | ((b & 0xF0) >> 4) for b in base]
            if check_key(nibble_swap, f"nibble_swap_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 3: Big integer interpretation
# ============================================================================
print("\n[3] Big integer operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Sum all shells into one big number, then extract bytes
        total = sum(shell_m)
        for div in [1, 7, 64, 127]:
            val = total // div
            # Extract 32 bytes from this big number
            pairs = [(val >> (8 * i)) & 0xFF for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"bigint_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: Use Outer or Inner areas directly
# ============================================================================
print("\n[4] Using Outer and Inner areas...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer_m = outer.copy()
        inner_m = inner.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for div in [64, 128, 256]:
            # Outer only
            pairs = [(outer_m[i*2] + outer_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"outer_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Inner only
            pairs = [(inner_m[i*2] + inner_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"inner_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 5: Width/Height instead of area
# ============================================================================
print("\n[5] Approximating width/height from areas...")

# For a rectangle with area A and known outer/inner, we might be able to derive dimensions
# But we don't have explicit width/height data, so let's try ratios

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        outer_m = outer.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [1, 7, 64]:
            # Ratio of outer to inner
            pairs = []
            for i in range(32):
                if inner[i*2] > 0 and inner[i*2+1] > 0:
                    r1 = outer[i*2] * 100 // inner[i*2]
                    r2 = outer[i*2+1] * 100 // inner[i*2+1]
                    val = (r1 + r2) // div % 256
                else:
                    val = 0
                pairs.append(val)
            if 119 in pairs:
                if check_key(pairs, f"ratio_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 6: Special byte positions with 0x77
# ============================================================================
print("\n[6] Setting specific positions to 0x77...")

# Maybe the puzzle requires certain bytes to be 0x77
# Based on 09111819: positions 0, 9, 11, 18, 19

positions_to_set = [
    [19],  # Position 19 already gives 119 with div7
    [0, 9, 11, 18, 19],  # All from 09111819
    [9, 18, 19],  # Just the non-zero/non-one digits
    [0, 19],  # First and 19
]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            for positions in positions_to_set:
                pairs = base.copy()
                for pos in positions:
                    if pos < 32:
                        pairs[pos] = 119
                if check_key(pairs, f"set77_pos{positions}_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 7: BIP39/mnemonic style derivation
# ============================================================================
print("\n[7] Hash-based derivation styles...")

import hmac

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        data = bytes([(shell_m[i*2] + shell_m[i*2+1]) % 256 for i in range(32)])

        # HMAC-SHA256
        h = hmac.new(b'zden', data, hashlib.sha256).digest()
        if check_key(list(h), f"hmac_m{mult40}_{mult53}"):
            exit()

        # PBKDF2-style (simplified)
        h = hashlib.pbkdf2_hmac('sha256', data, b'zden', 1)
        if check_key(list(h), f"pbkdf2_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Test 8: Interpret as WIF and decode
# ============================================================================
print("\n[8] Alternative interpretations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # As ASCII characters (filter printable)
            ascii_str = ''.join(chr(b) if 32 <= b < 127 else '?' for b in base)
            # print(f"  div{div} m{mult40}_{mult53} ASCII: {ascii_str}")

            # If it looks like hex, try to decode
            hex_str = ''.join(f'{b:02x}' for b in base)
            # Try first/last 32 chars as key
            try:
                if len(hex_str) >= 64:
                    key_bytes = bytes.fromhex(hex_str[:64])
                    if check_key(list(key_bytes), f"hex_first32_div{div}_m{mult40}_{mult53}"):
                        exit()
            except:
                pass

print("\nAlternative format search complete.")
