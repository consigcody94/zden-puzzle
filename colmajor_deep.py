"""
Deep exploration of column-major + offsets approach (which gave 119)
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
    except Exception as e:
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
    # Also check if close match (for debugging)
    if addr_c and addr_c.startswith("1crypto"):
        print(f"Close match! {desc}: {addr_c}")
    return False

offsets = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
offsets_32 = (offsets * 2)[:32]

# Column-major order
col_major = []
for col in range(8):
    for row in range(8):
        col_major.append(row * 8 + col)

print("Column-major index order:")
print(col_major)
print()

# Get shell areas with different multiplier combinations
def get_shell(mult40, mult53):
    shell = [r[2] for r in RECT_DATA]
    shell[39] *= mult40
    shell[52] *= mult53
    return shell

# The winning combination was column-major + offsets with div 16
# Let's explore variations

print("="*70)
print("EXPLORING COLUMN-MAJOR + OFFSETS (div 16 gave 119)")
print("="*70)

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        for div in range(10, 30):
            pairs = []
            for i in range(32):
                idx1 = col_major[i * 2]
                offset = offsets_32[i]
                idx2 = col_major[(i * 2 + 1 + offset) % 64]
                val = (shell[idx1] + shell[idx2]) // div
                pairs.append(val % 256)

            has_119 = 119 in pairs
            if has_119:
                pos_119 = [i for i, v in enumerate(pairs) if v == 119]
                print(f"m{mult40}_{mult53} div{div}: 119 at positions {pos_119}")
                if check_key(pairs, f"colmaj_m{mult40}_{mult53}_div{div}"):
                    exit()

# Try without 0x77 constraint (maybe it was a red herring or at different position)
print("\n" + "="*70)
print("Trying without 0x77 constraint")
print("="*70)

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        for div in [15, 16, 17, 18, 32, 64]:
            pairs = []
            for i in range(32):
                idx1 = col_major[i * 2]
                offset = offsets_32[i]
                idx2 = col_major[(i * 2 + 1 + offset) % 64]
                val = (shell[idx1] + shell[idx2]) // div
                pairs.append(val % 256)

            privkey_hex = ''.join(f'{b:02x}' for b in pairs)
            addr_c = privkey_to_address(privkey_hex, True)
            addr_u = privkey_to_address(privkey_hex, False)
            print(f"m{mult40}_{mult53} div{div}:")
            print(f"  Bytes: {pairs}")
            print(f"  Key: {privkey_hex}")
            print(f"  Addr-C: {addr_c}")
            if addr_c == TARGET:
                print("  *** MATCH! ***")
                exit()

# Try different offset application methods
print("\n" + "="*70)
print("Different offset methods with column-major")
print("="*70)

shell = get_shell(17, 6)

# Method A: offset on idx1
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        offset = offsets_32[i]
        idx1 = col_major[(i * 2 + offset) % 64]
        idx2 = col_major[i * 2 + 1]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    has_119 = 119 in pairs
    print(f"Method A (offset on idx1) div{div}: 119={has_119}")
    if has_119:
        check_key(pairs, f"methodA_div{div}")

# Method B: offset on both
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        offset = offsets_32[i]
        idx1 = col_major[(i * 2 + offset) % 64]
        idx2 = col_major[(i * 2 + 1 + offset) % 64]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    has_119 = 119 in pairs
    print(f"Method B (offset on both) div{div}: 119={has_119}")
    if has_119:
        check_key(pairs, f"methodB_div{div}")

# Method C: offset determines which column-major position to use
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        offset = offsets_32[i]
        idx1 = col_major[i * 2]
        idx2 = col_major[offset % 64]  # offset directly picks the second
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    has_119 = 119 in pairs
    print(f"Method C (offset picks idx2) div{div}: 119={has_119}")
    if has_119:
        check_key(pairs, f"methodC_div{div}")

print("\nColumn-major exploration complete.")
