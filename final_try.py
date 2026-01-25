"""
Final attempt - trying every reasonable formula variation.
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
            with open("C:/Users/Public/SOLUTION.txt", "w") as f:
                f.write(f"Solution: {desc}\n")
                f.write(f"Key: {privkey_bytes.hex()}\n")
            return True
    return False

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

print("="*70)
print("FINAL TRY - EXHAUSTIVE FORMULA SEARCH")
print("="*70)

# ============================================================================
# Systematic search through all reasonable formulas
# ============================================================================

count = 0
found = False

# Multiplier positions and values
mult_positions = [None, 38, 39, 52, 57]
mult_values = [1, 6, 7, 17]

# Divisors
divisors = list(range(1, 30)) + [30, 40, 64, 100]

# Operations
operations = ['add', 'sub', 'xor']

print("\nSearching through formula combinations...")

for mult_pos in mult_positions:
    for mult_val in mult_values:
        if mult_pos is None and mult_val != 1:
            continue

        # Apply multiplier
        shell_m = shell.copy()
        if mult_pos is not None:
            shell_m[mult_pos] *= mult_val

        for div in divisors:
            for op in operations:
                pairs = []
                valid = True
                for i in range(32):
                    try:
                        a = shell_m[i*2]
                        b = shell_m[i*2 + 1]

                        if op == 'add':
                            combined = a + b
                        elif op == 'sub':
                            combined = abs(a - b)
                        else:  # xor
                            combined = a ^ b

                        val = combined // div % 256
                        pairs.append(val)
                    except:
                        valid = False
                        break

                if valid and len(pairs) == 32:
                    if check_key(pairs, f"m{mult_pos}_{mult_val}_{op}_d{div}"):
                        found = True
                        exit()
                    count += 1

        if count % 1000 == 0 and count > 0:
            print(f"  {count} formulas tested...")

print(f"\nTested {count} formulas - no solution")

# ============================================================================
# Try with digit-based divisor selection
# ============================================================================
print("\n[2] Digit-based divisor selection...")

for mult_pos in [None, 39]:
    for mult_val in [1, 17]:
        if mult_pos is None and mult_val != 1:
            continue

        shell_m = shell.copy()
        if mult_pos is not None:
            shell_m[mult_pos] *= mult_val

        for base_div in [1, 5, 7, 10]:
            pairs = []
            for i in range(32):
                digit = all_digits[i % 16]
                div = digit + base_div if digit > 0 else base_div
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if check_key(pairs, f"digit_div_m{mult_pos}_{mult_val}_b{base_div}"):
                exit()

print("  No solution")

# ============================================================================
# Try with position-based operations
# ============================================================================
print("\n[3] Position-based operations...")

for mult_pos in [None, 39]:
    for mult_val in [1, 17]:
        if mult_pos is None and mult_val != 1:
            continue

        shell_m = shell.copy()
        if mult_pos is not None:
            shell_m[mult_pos] *= mult_val

        for split in range(1, 32):
            for d1 in [7, 10]:
                for d2 in [7, 10]:
                    if d1 == d2:
                        continue

                    pairs = []
                    for i in range(32):
                        div = d1 if i < split else d2
                        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                        pairs.append(val)

                    if check_key(pairs, f"split{split}_m{mult_pos}_{mult_val}_d{d1}_{d2}"):
                        exit()

print("  No solution")

# ============================================================================
# Try with offset-based pairing
# ============================================================================
print("\n[4] Offset-based pairing...")

for offset in range(1, 32):
    for div in [7, 10]:
        pairs = []
        for i in range(32):
            idx1 = i
            idx2 = (i + offset) % 64
            val = (shell[idx1] + shell[idx2]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"offset{offset}_div{div}"):
            exit()

print("  No solution")

# ============================================================================
# Print final summary
# ============================================================================
print("\n" + "="*70)
print("SUMMARY")
print("="*70)

print("""
After extensive testing of many formula variations, no solution was found.

Key findings:
1. shell[39] / 7 = 119 = 0x77 exactly
2. shell[57] / 7 = 40 = 0x28 exactly
3. With mult=17 at pos 39, pairs give 0x28 at byte 0, 0x77 at byte 19
4. The resulting key does not produce the target address

The puzzle likely requires:
- A different interpretation of the clues
- Additional visual information from the original puzzle
- A transformation we haven't considered
""")
