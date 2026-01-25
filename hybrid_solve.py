"""
We need BOTH:
1. First byte = 0x28 (requires div7 at position 0)
2. Byte 19 = 0x77 (requires div7 at position 19)

The digit at position 0 is 0 (even) -> div7 ✓
The digit at position 19 is 1 (odd) -> div10 ✗

We need a scheme where BOTH positions use div7.

Ideas:
1. Ignore parity for certain key positions
2. Use a different digit-to-divisor mapping
3. Use threshold instead of parity (e.g., digit <= 2 -> div7)
4. Rotate the digit sequence
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
print("HYBRID APPROACH - GET BOTH 0x28 AND 0x77")
print("="*70)

shell_m = shell.copy()
shell_m[39] *= 17

# ============================================================================
# 1. Force positions 0 and 19 to use div7, others use digit-based selection
# ============================================================================
print("\n[1] Force div7 at positions 0 and 19...")

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1

    if i == 0 or i == 19:
        div = 7  # Force div7 for key positions
    elif digit % 2 == 0:
        div = 7
    else:
        div = 10

    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at: {has_77}")
print(f"Key: {bytes(pairs).hex()}")

if check_key(pairs, "force_div7_0_19"):
    exit()

# Single byte modification
for pos in range(32):
    for val in range(256):
        test_pairs = pairs.copy()
        test_pairs[pos] = val
        if check_key(test_pairs, f"hybrid_mod_{pos}_{val}"):
            exit()

print("  Single byte mod on hybrid: no solution")

# ============================================================================
# 2. Use threshold: digit <= 1 -> div7, digit > 1 -> div10
#    Position 0: digit=0 (<=1) -> div7 ✓
#    Position 19: digit=1 (<=1) -> div7 ✓
# ============================================================================
print("\n[2] Threshold: digit <= 1 -> div7...")

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1

    if digit <= 1:
        div = 7
    else:
        div = 10

    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at: {has_77}")
print(f"Key: {bytes(pairs).hex()}")

if check_key(pairs, "threshold_le1"):
    exit()

# ============================================================================
# 3. Rotate the digit sequence
# ============================================================================
print("\n[3] Rotated digit sequences...")

for rotation in range(16):
    rotated = all_digits[rotation:] + all_digits[:rotation]

    pairs = []
    for i in range(32):
        digit = rotated[i % 16]
        idx1 = i * 2
        idx2 = i * 2 + 1

        if digit % 2 == 0:
            div = 7
        else:
            div = 10

        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    if pairs[0] == 0x28 and 0x77 in pairs:
        pos_77 = [j for j,p in enumerate(pairs) if p==0x77]
        print(f"  Rotation {rotation}: first={hex(pairs[0])}, 0x77 at {pos_77}")
        if check_key(pairs, f"rotation_{rotation}"):
            exit()

# ============================================================================
# 4. Use seq1 for first 16 bytes, seq2 for last 16 bytes (not cyclic)
# ============================================================================
print("\n[4] Separate sequences for each half...")

for d1 in [7, 10]:
    for d2 in [7, 10]:
        pairs = []
        for i in range(32):
            if i < 16:
                digit = seq1[i % 8]
            else:
                digit = seq2[(i - 16) % 8]

            idx1 = i * 2
            idx2 = i * 2 + 1

            if digit % 2 == 0:
                div = d1
            else:
                div = d2

            val = (shell_m[idx1] + shell_m[idx2]) // div % 256
            pairs.append(val)

        if pairs[0] == 0x28 and 0x77 in pairs:
            pos_77 = [j for j,p in enumerate(pairs) if p==0x77]
            print(f"  d1={d1}, d2={d2}: first={hex(pairs[0])}, 0x77 at {pos_77}")
            if check_key(pairs, f"separate_d{d1}_{d2}"):
                exit()

# ============================================================================
# 5. Use each 8-digit sequence for 8 bytes, then repeat
# ============================================================================
print("\n[5] 8-byte blocks from each sequence...")

pairs = []
for i in range(32):
    block = i // 8  # 0, 1, 2, 3
    pos_in_block = i % 8

    if block % 2 == 0:  # Blocks 0, 2 use seq1
        digit = seq1[pos_in_block]
    else:  # Blocks 1, 3 use seq2
        digit = seq2[pos_in_block]

    idx1 = i * 2
    idx2 = i * 2 + 1

    if digit % 2 == 0:
        div = 7
    else:
        div = 10

    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at: {has_77}")

if check_key(pairs, "8byte_blocks"):
    exit()

# ============================================================================
# 6. Just use div7 for all bytes (simple case)
# ============================================================================
print("\n[6] All div7...")

pairs = []
for i in range(32):
    idx1 = i * 2
    idx2 = i * 2 + 1
    val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at: {has_77}")
print(f"Key: {bytes(pairs).hex()}")

# This gives 0x28 at 0 and 0x77 at 19!
# Let's do extensive single-byte modification on this
print("\n  Single byte modification on all-div7 key...")

for pos in range(32):
    for val in range(256):
        test_pairs = pairs.copy()
        test_pairs[pos] = val
        if check_key(test_pairs, f"alldiv7_mod_{pos}_{val}"):
            exit()

print("  No solution with single byte mod")

# ============================================================================
# 7. Two-byte modification at non-critical positions
# ============================================================================
print("\n[7] Two-byte modification at non-critical positions...")

base = pairs.copy()  # All div7 key

# Positions to try (avoiding 0 and 19 which have the right values)
test_positions = [1, 2, 3, 4, 5, 10, 15, 20, 25, 30, 31]

count = 0
for p1 in test_positions:
    for p2 in test_positions:
        if p1 >= p2:
            continue
        for v1 in range(0, 256, 8):  # Step by 8 for speed
            for v2 in range(0, 256, 8):
                test_pairs = base.copy()
                test_pairs[p1] = v1
                test_pairs[p2] = v2
                if check_key(test_pairs, f"2byte_{p1}_{p2}"):
                    exit()
                count += 1

print(f"  Checked {count} two-byte combinations: no solution")

# ============================================================================
# 8. The key with all div7 is our best candidate - let's analyze it
# ============================================================================
print("\n[8] Analysis of all-div7 key...")

print(f"Key: {bytes(base).hex()}")
print(f"Address: {privkey_to_address(bytes(base), True)}")
print(f"Target:  {TARGET}")

# Check the address prefix
actual_addr = privkey_to_address(bytes(base), True)
if actual_addr:
    print(f"\nAddress comparison:")
    print(f"Actual:  {actual_addr}")
    print(f"Target:  {TARGET}")
    # Find first mismatch
    for i, (a, t) in enumerate(zip(actual_addr, TARGET)):
        if a != t:
            print(f"First mismatch at position {i}: '{a}' vs '{t}'")
            break

# ============================================================================
# 9. Try with different multiplier values
# ============================================================================
print("\n[9] Different multiplier values at position 39...")

for mult in [1, 7, 8, 14, 15, 16, 17, 18, 19, 20, 21, 119]:
    shell_m = shell.copy()
    shell_m[39] *= mult

    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
        pairs.append(val)

    if pairs[0] == 0x28:
        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  mult={mult}: first={hex(pairs[0])}, 0x77 at {has_77}")
            if check_key(pairs, f"mult_{mult}"):
                exit()

print("\n" + "="*70)
print("Hybrid approach complete")
print("="*70)

# Final summary
print("\nBest candidate (all div7, mult17 at 39):")
shell_m = shell.copy()
shell_m[39] *= 17
pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
print(f"Key: {bytes(pairs).hex()}")
print(f"First: {hex(pairs[0])}, Byte 19: {hex(pairs[19])}")
