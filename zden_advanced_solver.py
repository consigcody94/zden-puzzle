"""
Advanced Zden Level 5 Solver
Focus on decoding: 09111819 FIN 11122111 and -1*x+64/x/
"""
import hashlib
import ecdsa
import base58
import itertools

# Rectangle data (Outer, Inner, Shell)
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

def check_key(privkey_hex, desc=""):
    if len(privkey_hex) != 64:
        return False
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
    """Get areas with custom multipliers"""
    idx_map = {'outer': 0, 'inner': 1, 'shell': 2}
    idx = idx_map.get(area_type, 2)
    areas = [r[idx] for r in RECT_DATA]
    areas[39] *= mult40  # Rectangle #40
    areas[52] *= mult53  # Rectangle #53
    return areas

# Interpretation 1: 09111819 as pairing offsets
def pair_by_offset_sequence(areas, seq):
    """Use sequence as pairing offsets"""
    pairs = []
    for i in range(32):
        idx1 = i * 2
        offset = seq[i % len(seq)]
        idx2 = idx1 + offset
        if idx2 >= 64:
            idx2 = idx2 % 64
        pairs.append(areas[idx1] + areas[idx2])
    return pairs

# Interpretation 2: 09111819 tells which measurement to use
def mixed_measurement_approach(seq1, seq2):
    """Use different measurement types based on sequence"""
    # 0 = outer, 1 = inner, 9 = shell (9 % 3 = 0, so maybe shell)
    measurement_map = {0: 0, 1: 1, 2: 2, 8: 2, 9: 2}  # Try various mappings
    areas = []
    full_seq = (seq1 + seq2) * 4  # Extend to 64

    for i in range(64):
        digit = full_seq[i % len(full_seq)]
        mtype = measurement_map.get(digit, 2)
        areas.append(RECT_DATA[i][mtype])
    return areas

# Interpretation 3: Formula -1*x+64/x/
def apply_formula(value):
    """Apply the hint formula: -1*x+64 or (64-x)/x or 64/x - 1"""
    if value == 0:
        return 0
    # Try: 64/x - 1 (when x > 0)
    return int(64 / value) if value != 0 else 0

def apply_formula_v2(value):
    """Alternative: (64 - (value % 64))"""
    return (64 - (value % 64)) % 256

def apply_formula_v3(value, idx):
    """Use formula with index: (-1)^idx * value + 64"""
    sign = -1 if idx % 2 == 0 else 1
    return abs(sign * value + 64) % 256

# Interpretation 4: FIN means "Fibonacci Index Numbers"
def fibonacci_pairing(areas):
    """Pair using Fibonacci indices"""
    fib = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
    pairs = []
    for i in range(32):
        idx1 = (i * 2) % 64
        idx2 = (idx1 + fib[i % len(fib)]) % 64
        pairs.append(areas[idx1] + areas[idx2])
    return pairs

# Interpretation 5: "LHIU" = indices in some order
def lhiu_interpretation(areas):
    """L=50, H=8, I=9, U=21 (A=1 encoding) or positions"""
    # Try reading rectangles in LHIU order
    # Or LHIU = Left, Height, Inner, Unknown?
    pass

# Interpretation 6: Non-consecutive means alternating rows
def alternating_row_pairs(areas):
    """Pair rect from row 0 with rect from row 2, etc."""
    pairs = []
    for col in range(8):
        for row_pair in [(0, 2), (1, 3), (4, 6), (5, 7)]:
            idx1 = row_pair[0] * 8 + col
            idx2 = row_pair[1] * 8 + col
            pairs.append(areas[idx1] + areas[idx2])
    return pairs

# Interpretation 7: XOR instead of SUM
def xor_pairs(areas, pairing='consecutive'):
    """XOR instead of adding"""
    pairs = []
    for i in range(0, 64, 2):
        pairs.append(areas[i] ^ areas[i+1])
    return pairs

# Normalization functions
def norm_mod(values, n=256):
    return [v % n for v in values]

def norm_div(values, d):
    return [(v // d) % 256 for v in values]

def norm_shift(values, shift):
    return [(v >> shift) % 256 for v in values]

def norm_formula(values):
    """Apply -1*x+64 per byte"""
    return [(-v + 64) % 256 for v in values]

def bytes_to_hex(byte_list):
    return ''.join(f'{b:02x}' for b in byte_list)

def run_advanced():
    print("Advanced Zden LVL5 Solver")
    print("=" * 50)
    print(f"Target: {TARGET}\n")

    seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
    seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
    full_seq = seq1 + seq2

    checked = 0

    # Test mixed measurement approach
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            for area_type in ['outer', 'inner', 'shell']:
                areas = get_areas(area_type, mult40, mult53)

                # Test various pairing methods
                pairing_methods = [
                    ('offset_seq', lambda a: pair_by_offset_sequence(a, full_seq)),
                    ('fibonacci', fibonacci_pairing),
                    ('alt_rows', alternating_row_pairs),
                    ('xor', xor_pairs),
                ]

                for pair_name, pair_func in pairing_methods:
                    try:
                        pairs = pair_func(areas)
                        if pairs and len(pairs) == 32:
                            # Test various normalizations
                            for norm_name, norm_func in [
                                ('mod256', lambda v: norm_mod(v)),
                                ('div8', lambda v: norm_div(v, 8)),
                                ('div16', lambda v: norm_div(v, 16)),
                                ('div32', lambda v: norm_div(v, 32)),
                                ('div64', lambda v: norm_div(v, 64)),
                                ('shift4', lambda v: norm_shift(v, 4)),
                                ('shift8', lambda v: norm_shift(v, 8)),
                                ('formula', norm_formula),
                            ]:
                                normalized = norm_func(pairs)
                                key = bytes_to_hex(normalized)
                                desc = f"{area_type}_{pair_name}_{norm_name}_m{mult40}_{mult53}"
                                if check_key(key, desc):
                                    return key
                                checked += 1
                    except Exception as e:
                        pass

    # Try the mixed measurement approach
    print("\nTrying mixed measurement approach...")
    mixed_areas = mixed_measurement_approach(seq1, seq2)
    for i in range(0, 64, 2):
        pairs = [mixed_areas[i] + mixed_areas[i+1] for i in range(0, 64, 2)]
        for norm_func in [norm_mod, lambda v: norm_div(v, 64), norm_formula]:
            normalized = norm_func(pairs)
            key = bytes_to_hex(normalized)
            if check_key(key, "mixed_measurement"):
                return key
            checked += 1

    # Try treating the digits directly as relating to rectangle indices
    print("\nTrying digit-as-index approach...")
    # 09111819 11122111 could mean pairs: (0,9), (1,1), (1,8), (1,9), (1,1), (1,2), (2,1), (1,1)
    digit_pairs = [(0,9), (1,1), (1,8), (1,9), (1,1), (1,2), (2,1), (1,1)]

    for area_type in ['shell', 'outer', 'inner']:
        areas = get_areas(area_type, 17, 6)

        # Extended interpretation: repeat pattern for 32 pairs
        extended_pairs = (digit_pairs * 4)[:32]

        pairs = []
        for i, (offset1, offset2) in enumerate(extended_pairs):
            base_idx = i * 2
            idx1 = (base_idx + offset1) % 64
            idx2 = (base_idx + offset2) % 64
            pairs.append(areas[idx1] + areas[idx2])

        for norm_name, norm_func in [('mod256', norm_mod), ('div64', lambda v: norm_div(v, 64))]:
            normalized = norm_func(pairs)
            key = bytes_to_hex(normalized)
            if check_key(key, f"digit_pairs_{area_type}_{norm_name}"):
                return key
            checked += 1

    print(f"\nChecked {checked} combinations. No match.")
    print("\nKey insights needed:")
    print("1. The '09111819 FIN 11122111' encoding")
    print("2. The '-1*x+64/x/' formula application")
    print("3. Correct interpretation of strikethrough 'consecutive'")

if __name__ == "__main__":
    run_advanced()
