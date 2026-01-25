"""
Zden Level 5 Bitcoin Puzzle Solver
Target: 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7

Key observations:
- 64 rectangles in 8x8 grid
- "consecutive" is STRUCK THROUGH - meaning NON-consecutive pairing
- Mini-puzzle: 09111819 FIN 11122111
- Special: rect #40 has 17px line, #53 has 6px line
- Formula hint: -1*x+64/x/
"""

import hashlib
import itertools

# Rectangle areas from the analysis (Outer, Inner, Shell)
# 64 rectangles in reading order (row by row, left to right)
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
    (4453, 3213, 1240), (3550, 2332, 1218), (1472, 560, 912), (1139, 300, 839),  # #40 (index 39)
    (690, 30, 660), (1419, 961, 458), (3472, 2352, 1120), (2898, 1764, 1134),
    (672, 224, 448), (1173, 123, 1050), (2184, 1404, 780), (1581, 527, 1054),
    (7476, 6006, 1470), (2793, 1961, 832), (3484, 2530, 954), (5280, 4042, 1238),
    (126, 8, 118), (120, 32, 88),  # #53 (index 52), #54 (index 53)
    (3705, 2303, 1402), (5200, 3332, 1868),
    (5829, 4187, 1642), (2537, 2255, 282), (1632, 720, 912), (3894, 2296, 1598),
    (4130, 3762, 368), (2288, 768, 1520), (1380, 380, 1000), (1856, 1200, 656),
]

TARGET_ADDRESS = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

def get_areas(area_type='shell', apply_multipliers=True):
    """Extract specific area type from rectangle data"""
    idx_map = {'outer': 0, 'inner': 1, 'shell': 2}
    idx = idx_map.get(area_type, 2)
    areas = [r[idx] for r in RECT_DATA]

    if apply_multipliers:
        # Rectangle #40 (index 39) has 17px line
        # Rectangle #53 (index 52) has 6px line
        areas[39] = areas[39] * 17
        areas[52] = areas[52] * 6

    return areas

def pair_consecutive(areas):
    """Pair consecutive: [0+1], [2+3], ..."""
    return [areas[i] + areas[i+1] for i in range(0, 64, 2)]

def pair_skip_one(areas):
    """Pair with skip: [0+2], [1+3], [4+6], [5+7], ..."""
    pairs = []
    for row in range(8):
        base = row * 8
        for i in range(0, 8, 4):
            pairs.append(areas[base+i] + areas[base+i+2])
            pairs.append(areas[base+i+1] + areas[base+i+3])
    return pairs

def pair_vertical(areas):
    """Pair vertically: [0+8], [1+9], [2+10], ..."""
    return [areas[i] + areas[i+8] for i in range(32)]

def pair_diagonal(areas):
    """Pair diagonally: [0+9], [1+10], [2+11], ..."""
    pairs = []
    for row in range(0, 8, 2):
        for col in range(8):
            idx1 = row * 8 + col
            idx2 = (row + 1) * 8 + (col + 1) % 8
            pairs.append(areas[idx1] + areas[idx2])
    return pairs

def pair_columns(areas):
    """Pair by columns: [col0_row0 + col0_row1], ..."""
    pairs = []
    for col in range(8):
        for row in range(0, 8, 2):
            idx1 = row * 8 + col
            idx2 = (row + 1) * 8 + col
            pairs.append(areas[idx1] + areas[idx2])
    return pairs

def pair_following_non_consecutive(areas):
    """
    "following" but NOT consecutive - maybe fibonacci-like?
    Sum rect[n] + rect[n+fib] where fib cycles through 1,2,3,5,8...
    """
    fib = [1, 2, 3, 5, 8, 13, 21, 34]
    pairs = []
    used = set()
    i = 0
    fib_idx = 0
    while len(pairs) < 32 and i < 64:
        j = i + fib[fib_idx % len(fib)]
        if j < 64 and i not in used and j not in used:
            pairs.append(areas[i] + areas[j])
            used.add(i)
            used.add(j)
        i += 1
        if i in used:
            i += 1
        fib_idx += 1
    return pairs if len(pairs) == 32 else None

def normalize_mod256(values):
    """Simple modulo 256"""
    return [v % 256 for v in values]

def normalize_scale(values):
    """Scale to 0-255 based on max value"""
    max_v = max(values)
    return [int((v / max_v) * 255) for v in values]

def normalize_minmax(values):
    """Min-max normalization to 0-255"""
    min_v, max_v = min(values), max(values)
    if max_v == min_v:
        return [128] * len(values)
    return [int(((v - min_v) / (max_v - min_v)) * 255) for v in values]

def normalize_div64(values):
    """Divide by 64 then mod 256 (from hint -1*x+64/x/)"""
    return [(v // 64) % 256 for v in values]

def bytes_to_privkey(byte_list):
    """Convert byte list to hex private key"""
    return ''.join(f'{b:02x}' for b in byte_list)

def privkey_to_wif(privkey_hex, compressed=True):
    """Convert hex private key to WIF format"""
    extended = '80' + privkey_hex
    if compressed:
        extended += '01'

    # Double SHA256
    first_hash = hashlib.sha256(bytes.fromhex(extended)).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]

    final = bytes.fromhex(extended) + checksum

    # Base58 encode
    alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    num = int.from_bytes(final, 'big')
    result = ''
    while num > 0:
        num, rem = divmod(num, 58)
        result = alphabet[rem] + result

    # Add leading 1s for leading zeros
    for byte in final:
        if byte == 0:
            result = '1' + result
        else:
            break

    return result

def pubkey_to_address(privkey_hex):
    """Derive Bitcoin address from private key (simplified - needs ecdsa)"""
    # This would need the ecdsa library for full implementation
    # For now, return the private key for manual verification
    return privkey_hex

def try_combination(area_type, pairing_func, normalize_func, apply_mult=True):
    """Try a specific combination and return the private key"""
    areas = get_areas(area_type, apply_mult)
    pairs = pairing_func(areas)
    if pairs is None or len(pairs) != 32:
        return None
    normalized = normalize_func(pairs)
    return bytes_to_privkey(normalized)

# Mini-puzzle decoder
def decode_mini_puzzle():
    """
    Mini puzzle shows: 09111819 FIN 11122111
    Could be: indices, transformation codes, or pairing offsets
    """
    seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # First sequence
    seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # Second sequence
    return seq1, seq2

def pair_by_mini_puzzle(areas):
    """
    Use mini-puzzle indices for pairing
    09111819: use digits as offsets?
    """
    seq1, seq2 = decode_mini_puzzle()
    # Interpretation: pair rect[i] with rect[i + offset] where offset from sequences
    pairs = []
    offsets = seq1 + seq2 + seq1 + seq2  # Repeat to get 32 offsets

    for i in range(32):
        idx1 = i * 2
        offset = offsets[i % len(offsets)]
        idx2 = (idx1 + offset) % 64
        if idx1 < 64 and idx2 < 64:
            pairs.append(areas[idx1] + areas[idx2])

    return pairs if len(pairs) == 32 else None

# Test all combinations
def run_solver():
    print("=" * 60)
    print("ZDEN LEVEL 5 SOLVER")
    print("Target: " + TARGET_ADDRESS)
    print("=" * 60)

    area_types = ['outer', 'inner', 'shell']
    pairing_funcs = [
        ('consecutive', pair_consecutive),
        ('skip_one', pair_skip_one),
        ('vertical', pair_vertical),
        ('diagonal', pair_diagonal),
        ('columns', pair_columns),
        ('mini_puzzle', pair_by_mini_puzzle),
    ]
    normalize_funcs = [
        ('mod256', normalize_mod256),
        ('scale', normalize_scale),
        ('minmax', normalize_minmax),
        ('div64', normalize_div64),
    ]

    results = []

    for area_type in area_types:
        for pair_name, pair_func in pairing_funcs:
            for norm_name, norm_func in normalize_funcs:
                for apply_mult in [True, False]:
                    key = try_combination(area_type, pair_func, norm_func, apply_mult)
                    if key:
                        mult_str = "mult" if apply_mult else "nomult"
                        combo = f"{area_type}_{pair_name}_{norm_name}_{mult_str}"
                        wif_c = privkey_to_wif(key, compressed=True)
                        wif_u = privkey_to_wif(key, compressed=False)
                        results.append((combo, key, wif_c, wif_u))
                        print(f"\n{combo}:")
                        print(f"  HEX: {key}")
                        print(f"  WIF-C: {wif_c}")

    print(f"\n\nGenerated {len(results)} candidate keys")
    print("\nTo verify, use: https://www.bitaddress.org or similar")
    print("Check if any WIF generates address: " + TARGET_ADDRESS)

    return results

if __name__ == "__main__":
    results = run_solver()

    # Save results
    with open("C:/Users/Public/zden_keys.txt", "w") as f:
        f.write(f"Target: {TARGET_ADDRESS}\n\n")
        for combo, key, wif_c, wif_u in results:
            f.write(f"{combo}\n")
            f.write(f"  HEX: {key}\n")
            f.write(f"  WIF-C: {wif_c}\n")
            f.write(f"  WIF-U: {wif_u}\n\n")

    print("\nResults saved to C:/Users/Public/zden_keys.txt")
