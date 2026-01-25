"""
Comprehensive brute-force search for Zden Level 5
Using multiprocessing to parallelize the search
"""
import hashlib
import ecdsa
import base58
import itertools
import multiprocessing as mp
from functools import partial
import time
import sys

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

# Pre-compute shell areas
SHELL = [r[2] for r in RECT_DATA]
OUTER = [r[0] for r in RECT_DATA]
INNER = [r[1] for r in RECT_DATA]

def privkey_to_address(privkey_bytes, compressed=True):
    """Fast address derivation"""
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

def check_candidate(byte_list):
    """Check if bytes produce target address"""
    if len(byte_list) != 32:
        return None
    privkey_bytes = bytes(byte_list)
    addr_c = privkey_to_address(privkey_bytes, True)
    if addr_c == TARGET:
        return ('compressed', byte_list)
    addr_u = privkey_to_address(privkey_bytes, False)
    if addr_u == TARGET:
        return ('uncompressed', byte_list)
    return None

def generate_pairing_patterns():
    """Generate different pairing patterns to try"""
    patterns = []

    # 1. Consecutive (standard)
    patterns.append(('consecutive', [(i*2, i*2+1) for i in range(32)]))

    # 2. Various skip patterns
    for skip in range(2, 16):
        pairs = [(i, (i + skip) % 64) for i in range(32)]
        patterns.append((f'skip_{skip}', pairs))

    # 3. Column-major
    col_major = []
    for col in range(8):
        for row in range(8):
            col_major.append(row * 8 + col)
    patterns.append(('col_major', [(col_major[i*2], col_major[i*2+1]) for i in range(32)]))

    # 4. Diagonal patterns
    for offset in range(1, 8):
        pairs = []
        for i in range(32):
            row = (i * 2) // 8
            col = (i * 2) % 8
            idx1 = row * 8 + col
            idx2 = ((row + offset) % 8) * 8 + ((col + offset) % 8)
            pairs.append((idx1, idx2))
        patterns.append((f'diagonal_{offset}', pairs))

    # 5. Mini-puzzle based offsets
    offsets = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
    for base in range(4):
        pairs = []
        for i in range(32):
            idx1 = i * 2
            off = offsets[(i + base) % len(offsets)]
            idx2 = (idx1 + 1 + off) % 64
            pairs.append((idx1, idx2))
        patterns.append((f'offset_base{base}', pairs))

    # 6. Reverse patterns
    patterns.append(('reverse', [(63 - i*2, 63 - i*2 - 1) for i in range(32)]))

    # 7. Interleaved
    patterns.append(('interleaved', [(i, i + 32) for i in range(32)]))

    # 8. Zigzag
    zigzag = []
    for row in range(8):
        if row % 2 == 0:
            zigzag.extend(range(row*8, (row+1)*8))
        else:
            zigzag.extend(range((row+1)*8-1, row*8-1, -1))
    patterns.append(('zigzag', [(zigzag[i*2], zigzag[i*2+1]) for i in range(32)]))

    return patterns

def generate_operations():
    """Generate different arithmetic operations to try"""
    operations = []

    # Basic: (a + b) // div
    for div in range(1, 256):
        operations.append((f'sum_div{div}', lambda a, b, d=div: (a + b) // d % 256))

    # XOR variants
    for shift in range(1, 16):
        operations.append((f'xor_shift{shift}', lambda a, b, s=shift: ((a >> s) ^ (b >> s)) % 256))

    # Subtraction
    for div in [1, 8, 16, 32, 64, 128]:
        operations.append((f'sub_div{div}', lambda a, b, d=div: abs(a - b) // d % 256))

    # Weighted
    for w1, w2 in [(17, 6), (6, 17), (17, 7), (7, 17), (17, 1), (1, 17)]:
        for div in [32, 64, 128, 256]:
            operations.append((f'weighted_{w1}_{w2}_div{div}',
                             lambda a, b, wa=w1, wb=w2, d=div: (a * wa + b * wb) // d % 256))

    return operations

def test_combination(args):
    """Test a single pairing + operation combination"""
    pattern_name, pairs, op_name, operation, mult40, mult53, area_type = args

    # Get areas
    if area_type == 'shell':
        areas = SHELL.copy()
    elif area_type == 'outer':
        areas = OUTER.copy()
    else:
        areas = INNER.copy()

    # Apply multipliers
    areas[39] *= mult40
    areas[52] *= mult53

    # Generate bytes
    try:
        byte_list = []
        for idx1, idx2 in pairs:
            val = operation(areas[idx1], areas[idx2])
            byte_list.append(val)

        # Quick check: must contain 119
        if KNOWN_BYTE not in byte_list:
            return None

        # Full address check
        result = check_candidate(byte_list)
        if result:
            return (pattern_name, op_name, mult40, mult53, area_type, result)

    except Exception as e:
        pass

    return None

def main():
    print("="*70)
    print("BRUTE FORCE SEARCH")
    print("="*70)
    print(f"Target: {TARGET}")
    print(f"Required byte: 0x{KNOWN_BYTE:02x} ({KNOWN_BYTE})")
    print()

    # Generate all combinations to test
    patterns = generate_pairing_patterns()
    print(f"Pairing patterns: {len(patterns)}")

    # Simplified operations for speed
    divisors = list(range(1, 257))  # All possible divisors
    multipliers_40 = [1, 7, 17]
    multipliers_53 = [1, 6, 7]
    area_types = ['shell', 'outer', 'inner']

    total_combinations = len(patterns) * len(divisors) * len(multipliers_40) * len(multipliers_53) * len(area_types)
    print(f"Total combinations to test: {total_combinations:,}")
    print()

    # Use multiprocessing
    num_cpus = mp.cpu_count()
    print(f"Using {num_cpus} CPU cores")
    print("Starting search...")
    print()

    start_time = time.time()
    tested = 0
    found_119_count = 0

    # Build work items
    work_items = []

    for pattern_name, pairs in patterns:
        for div in divisors:
            operation = lambda a, b, d=div: (a + b) // d % 256
            op_name = f'div{div}'

            for mult40 in multipliers_40:
                for mult53 in multipliers_53:
                    for area_type in area_types:
                        work_items.append((pattern_name, pairs, op_name, operation, mult40, mult53, area_type))

    # Process in batches
    batch_size = 10000

    for batch_start in range(0, len(work_items), batch_size):
        batch = work_items[batch_start:batch_start + batch_size]

        # Test each item
        for item in batch:
            result = test_combination(item)
            tested += 1

            if result:
                elapsed = time.time() - start_time
                print(f"\n{'='*70}")
                print("SOLUTION FOUND!")
                print(f"{'='*70}")
                print(f"Pattern: {result[0]}")
                print(f"Operation: {result[1]}")
                print(f"Multipliers: rect40={result[2]}, rect53={result[3]}")
                print(f"Area type: {result[4]}")
                print(f"Key type: {result[5][0]}")
                key_hex = ''.join(f'{b:02x}' for b in result[5][1])
                print(f"Private key: {key_hex}")
                print(f"Tested: {tested:,} combinations in {elapsed:.1f}s")

                # Save solution
                with open("C:/Users/Public/SOLUTION_FOUND.txt", "w") as f:
                    f.write(f"Pattern: {result[0]}\n")
                    f.write(f"Operation: {result[1]}\n")
                    f.write(f"Multipliers: rect40={result[2]}, rect53={result[3]}\n")
                    f.write(f"Area type: {result[4]}\n")
                    f.write(f"Private key: {key_hex}\n")

                return

        # Progress update
        elapsed = time.time() - start_time
        rate = tested / elapsed if elapsed > 0 else 0
        print(f"\rTested: {tested:,} / {len(work_items):,} ({100*tested/len(work_items):.1f}%) - {rate:.0f}/sec", end='', flush=True)

    elapsed = time.time() - start_time
    print(f"\n\nSearch complete. Tested {tested:,} combinations in {elapsed:.1f}s")
    print("No solution found with basic operations.")
    print("\nTrying additional operations...")

    # Try more complex operations
    print("\n[Phase 2] XOR and weighted operations...")

    additional_ops = [
        ('xor', lambda a, b: (a ^ b) % 256),
        ('xor_shift4', lambda a, b: ((a >> 4) ^ (b >> 4)) % 256),
        ('xor_shift5', lambda a, b: ((a >> 5) ^ (b >> 5)) % 256),
        ('xor_shift6', lambda a, b: ((a >> 6) ^ (b >> 6)) % 256),
    ]

    for pattern_name, pairs in patterns:
        for op_name, operation in additional_ops:
            for mult40 in multipliers_40:
                for mult53 in multipliers_53:
                    for area_type in area_types:
                        item = (pattern_name, pairs, op_name, operation, mult40, mult53, area_type)
                        result = test_combination(item)
                        tested += 1

                        if result:
                            key_hex = ''.join(f'{b:02x}' for b in result[5][1])
                            print(f"\nSOLUTION: {result[0]}, {result[1]}, m{result[2]}_{result[3]}, {result[4]}")
                            print(f"Key: {key_hex}")
                            return

    print(f"\nTotal tested: {tested:,}")
    print("No solution found.")

if __name__ == "__main__":
    main()
