"""
Zden Level 5 Final Solver
CRITICAL HINT: Byte 0x77 (119) is part of the private key!
"""
import hashlib
import ecdsa
import base58
import itertools

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
KNOWN_BYTE = 0x77  # 119 decimal - this must be in the key!

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

    # CRITICAL: Check if 0x77 is in the key
    if KNOWN_BYTE not in byte_list:
        return False

    privkey_hex = ''.join(f'{b:02x}' for b in byte_list)
    addr_c = privkey_to_address(privkey_hex, True)
    addr_u = privkey_to_address(privkey_hex, False)

    if addr_c == TARGET or addr_u == TARGET:
        print(f"\n{'='*60}")
        print(f"FOUND! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"Addr-C: {addr_c}")
        print(f"Addr-U: {addr_u}")
        print(f"{'='*60}")
        return True
    return False

def get_areas(area_type='shell', mult40=1, mult53=1):
    idx_map = {'outer': 0, 'inner': 1, 'shell': 2}
    idx = idx_map.get(area_type, 2)
    areas = [r[idx] for r in RECT_DATA]
    areas[39] *= mult40
    areas[52] *= mult53
    return areas

# Find which pair sums could yield 119 (0x77)
def analyze_for_known_byte():
    """Find combinations that could produce byte 0x77 (119)"""
    print("Analyzing which rectangle pairs could produce 0x77 (119)...")
    print()

    for area_type in ['outer', 'inner', 'shell']:
        for mult40 in [1, 17]:
            for mult53 in [1, 6]:
                areas = get_areas(area_type, mult40, mult53)

                results_mod = []
                results_div = []

                for i in range(64):
                    for j in range(i+1, 64):
                        sum_val = areas[i] + areas[j]
                        if sum_val % 256 == 119:
                            results_mod.append((i, j, sum_val))
                        # Check various divisions
                        for div in [8, 16, 32, 64, 128]:
                            if (sum_val // div) % 256 == 119:
                                results_div.append((i, j, sum_val, div))

                if results_mod:
                    print(f"{area_type} m{mult40}_{mult53} - pairs giving 119 (mod 256):")
                    for i, j, s in results_mod[:5]:
                        print(f"  rect[{i}] + rect[{j}] = {s} -> {s % 256}")

def find_pairs_for_target():
    """
    Work backwards: for each position, find which rect pairs give 119
    """
    print("\nSearching for valid configurations with 0x77...")

    for area_type in ['shell', 'outer', 'inner']:
        for mult40 in [1, 17]:
            for mult53 in [1, 6]:
                areas = get_areas(area_type, mult40, mult53)

                # For SHELL with multipliers applied
                # Try different pairing strategies

                # Strategy 1: Consecutive with various divisions
                for divisor in [1, 2, 4, 8, 16, 32, 64]:
                    pairs = []
                    for i in range(0, 64, 2):
                        val = (areas[i] + areas[i+1]) // divisor
                        pairs.append(val % 256)

                    if check_key(pairs, f"{area_type}_consec_div{divisor}_m{mult40}_{mult53}"):
                        return

                # Strategy 2: Vertical pairing
                for divisor in [1, 2, 4, 8, 16, 32, 64]:
                    pairs = []
                    for col in range(8):
                        for row in range(0, 8, 2):
                            idx1 = row * 8 + col
                            idx2 = (row + 1) * 8 + col
                            val = (areas[idx1] + areas[idx2]) // divisor
                            pairs.append(val % 256)

                    if check_key(pairs, f"{area_type}_vert_div{divisor}_m{mult40}_{mult53}"):
                        return

                # Strategy 3: Column-wise (different order)
                for divisor in [1, 2, 4, 8, 16, 32, 64]:
                    pairs = []
                    for i in range(32):
                        idx1 = i
                        idx2 = i + 32
                        val = (areas[idx1] + areas[idx2]) // divisor
                        pairs.append(val % 256)

                    if check_key(pairs, f"{area_type}_halves_div{divisor}_m{mult40}_{mult53}"):
                        return

                # Strategy 4: Skip pattern (following, not consecutive)
                for skip in range(2, 10):
                    pairs = []
                    used = set()
                    for i in range(64):
                        if i in used:
                            continue
                        j = i + skip
                        if j >= 64 or j in used:
                            j = (i + 1) % 64
                        if j in used:
                            continue
                        if len(pairs) < 32:
                            val = areas[i] + areas[j]
                            pairs.append(val % 256)
                            used.add(i)
                            used.add(j)

                    if len(pairs) == 32:
                        if check_key(pairs, f"{area_type}_skip{skip}_m{mult40}_{mult53}"):
                            return

                # Strategy 5: Subtract instead of add (maybe "-1*x" means negative)
                for divisor in [1, 8, 16, 32, 64]:
                    pairs = []
                    for i in range(0, 64, 2):
                        val = abs(areas[i] - areas[i+1]) // divisor
                        pairs.append(val % 256)

                    if check_key(pairs, f"{area_type}_subtract_div{divisor}_m{mult40}_{mult53}"):
                        return

def main():
    print("Zden LVL5 Final Solver")
    print("=" * 50)
    print(f"Target: {TARGET}")
    print(f"Known byte in key: 0x77 ({KNOWN_BYTE})")
    print()

    analyze_for_known_byte()
    find_pairs_for_target()

    print("\nNo match found yet.")
    print("\nThe solution likely requires:")
    print("1. Correct interpretation of '09111819 FIN 11122111'")
    print("2. Understanding the mini-puzzle coordinate system")
    print("3. Applying the formula in a specific way")

if __name__ == "__main__":
    main()
