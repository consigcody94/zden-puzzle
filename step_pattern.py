"""
Deep exploration of the step pattern approach.

Key insight: Starting at index 57 with step 26 gives:
- 0x28 at position 0 (from shell[57]/7 = 40)
- 0x77 at position 19 or 20 (from shell[39]/7 = 119)

The sequence of indices with start=57, step=26:
57, 19, 45, 7, 33, 59, 21, 47, 9, 35, 61, 23, 49, 11, 37, 63,
25, 51, 13, 39, 1, 27, 53, 15, 41, 3, 29, 55, 17, 43, 5, 31

Index 39 appears at position 19! This matches our 0x77 finding.

Now let's try modifications and see what produces the target.
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
            with open("C:/Users/Public/SOLUTION.txt", "w") as f:
                f.write(f"Solution: {desc}\n")
                f.write(f"Key: {privkey_bytes.hex()}\n")
            return True
    return False

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

print("="*70)
print("STEP PATTERN DEEP EXPLORATION")
print("="*70)

# ============================================================================
# 1. Generate the step-26 from 57 pattern
# ============================================================================
print("\n[1] Step-26 from 57 analysis...")

start, step = 57, 26
indices = [(start + i * step) % 64 for i in range(32)]
print(f"Indices: {indices}")
print(f"Position of index 39: {indices.index(39) if 39 in indices else 'not found'}")

base_key = [shell[idx] // 7 % 256 for idx in indices]
print(f"Base key: {bytes(base_key).hex()}")
print(f"Byte 0: {hex(base_key[0])}, Byte 19: {hex(base_key[19])}")

# ============================================================================
# 2. Try multiplier at the index-39 position
# ============================================================================
print("\n[2] Multiplier at position with index 39...")

pos_39 = indices.index(39)
for mult in [17, 7, 10, 6, 9, 24]:
    shell_m = shell.copy()
    shell_m[39] *= mult

    key = [shell_m[idx] // 7 % 256 for idx in indices]
    addr = privkey_to_address(bytes(key), True)
    prefix_match = sum(1 for a, b in zip(addr or "", TARGET) if a == b) if addr else 0

    if prefix_match >= 2:
        print(f"  mult={mult}: {addr[:20]}... ({prefix_match} chars)")

    if check_key(key, f"step26_mult{mult}"):
        exit()

# ============================================================================
# 3. Try different step values that still hit index 39
# ============================================================================
print("\n[3] Steps that hit index 39...")

for start in range(64):
    for step in range(1, 64):
        if step == 1:  # Skip consecutive
            continue

        indices = [(start + i * step) % 64 for i in range(32)]

        # Check if 39 is in the sequence
        if 39 not in indices:
            continue

        # Check if we get 0x28 and 0x77
        key = [shell[idx] // 7 % 256 for idx in indices]

        if key[0] == 0x28 and 0x77 in key:
            pos_77 = [j for j, v in enumerate(key) if v == 0x77]
            print(f"  Start {start} step {step}: 0x77 at {pos_77}")

            # Try with multiplier at 39
            for mult in [17, 7, 10]:
                shell_m = shell.copy()
                shell_m[39] *= mult
                key_m = [shell_m[idx] // 7 % 256 for idx in indices]
                if check_key(key_m, f"start{start}_step{step}_mult{mult}"):
                    exit()

# ============================================================================
# 4. The digit sequence might modify specific bytes
# ============================================================================
print("\n[4] Digit sequence modifications...")

# Base key with step pattern
indices = [(57 + i * 26) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]

# Apply digit sequence as additions/XORs
for op in ['add', 'xor', 'sub']:
    key = base_key.copy()
    for i in range(32):
        digit = all_digits[i % 16]
        if op == 'add':
            key[i] = (key[i] + digit) % 256
        elif op == 'xor':
            key[i] = key[i] ^ digit
        else:  # sub
            key[i] = (key[i] - digit) % 256

    if check_key(key, f"step26_digit_{op}"):
        exit()

# ============================================================================
# 5. Use outer/inner at specific positions
# ============================================================================
print("\n[5] Mixed outer/inner/shell...")

for div in [7, 10]:
    # Use shell for most, outer for positions indicated by digits
    key = []
    for i, idx in enumerate(indices):
        digit = all_digits[i % 16]
        if digit == 0:
            val = shell[idx] // div % 256
        elif digit == 1:
            val = outer[idx] // div % 256
        elif digit == 2:
            val = inner[idx] // div % 256
        else:
            val = (outer[idx] + inner[idx]) // div % 256
        key.append(val)

    if check_key(key, f"mixed_div{div}"):
        exit()

# ============================================================================
# 6. Reverse or byte swap
# ============================================================================
print("\n[6] Byte ordering...")

indices = [(57 + i * 26) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]

# Reverse entire key
if check_key(base_key[::-1], "step26_reversed"):
    exit()

# Swap pairs of bytes
swapped = []
for i in range(0, 32, 2):
    swapped.append(base_key[i+1])
    swapped.append(base_key[i])
if check_key(swapped, "step26_pair_swapped"):
    exit()

# Reverse each 4-byte group (little endian words)
le_key = []
for i in range(0, 32, 4):
    le_key.extend(base_key[i:i+4][::-1])
if check_key(le_key, "step26_little_endian"):
    exit()

# ============================================================================
# 7. Different divisors at different positions
# ============================================================================
print("\n[7] Position-based divisors...")

for split in range(1, 32):
    key = []
    for i, idx in enumerate(indices):
        if i < split:
            val = shell[idx] // 7 % 256
        else:
            val = shell[idx] // 10 % 256
        key.append(val)

    if check_key(key, f"step26_split{split}"):
        exit()

# ============================================================================
# 8. Use the "FIX" position 39 as XOR mask
# ============================================================================
print("\n[8] FIX as XOR mask...")

fix_val = shell[39] // 7  # 119 = 0x77

for div in [7, 10]:
    key = []
    for idx in indices:
        val = (shell[idx] // div) ^ fix_val
        key.append(val % 256)

    if check_key(key, f"step26_xor_fix_div{div}"):
        exit()

# ============================================================================
# 9. Comprehensive single-byte modification search
# ============================================================================
print("\n[9] Single-byte modifications on step26...")

indices = [(57 + i * 26) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]

best_match = 0
for pos in range(32):
    for val in range(256):
        key = base_key.copy()
        key[pos] = val

        addr = privkey_to_address(bytes(key), True)
        if addr:
            match = sum(1 for a, b in zip(addr, TARGET) if a == b)
            if match > best_match:
                best_match = match
                print(f"  pos {pos} val {val}: {match} chars - {addr[:match+3]}...")

        if check_key(key, f"step26_mod_{pos}_{val}"):
            exit()

        # Also check uncompressed
        addr = privkey_to_address(bytes(key), False)
        if addr:
            match = sum(1 for a, b in zip(addr, TARGET) if a == b)
            if match > best_match:
                best_match = match
                print(f"  pos {pos} val {val} UNCOMP: {match} chars - {addr[:match+3]}...")

print(f"\nBest single-byte match: {best_match} characters")

# ============================================================================
# 10. Two-byte modifications
# ============================================================================
print("\n[10] Two-byte modifications (focused)...")

import itertools

# Focus on positions 0, 19 and a few others
focus_positions = [0, 1, 18, 19, 20, 31]

for p1, p2 in itertools.combinations(focus_positions, 2):
    for v1 in [0x28, 0x77, 0x00, 0xFF] + list(range(0, 256, 17)):
        for v2 in [0x28, 0x77, 0x00, 0xFF] + list(range(0, 256, 17)):
            key = base_key.copy()
            key[p1] = v1
            key[p2] = v2

            if check_key(key, f"step26_2mod_{p1}_{v1}_{p2}_{v2}"):
                exit()

print("  No solution with focused two-byte mods")

# ============================================================================
# 11. Try the LXIV hint - maybe divide by 64?
# ============================================================================
print("\n[11] LXIV (64) interpretations...")

for start in [0, 39, 57]:
    for step in [1, 2, 26]:
        indices = [(start + i * step) % 64 for i in range(32)]

        key = [shell[idx] // 64 % 256 for idx in indices]
        if 0x28 in key or 0x77 in key:
            pos_28 = [j for j, v in enumerate(key) if v == 0x28]
            pos_77 = [j for j, v in enumerate(key) if v == 0x77]
            print(f"  start{start} step{step} div64: 0x28@{pos_28}, 0x77@{pos_77}")

        if check_key(key, f"div64_start{start}_step{step}"):
            exit()

# ============================================================================
# 12. Sum with previous value (running sum)
# ============================================================================
print("\n[12] Running operations...")

indices = [(57 + i * 26) % 64 for i in range(32)]

for div in [7, 10]:
    # Running sum
    key = []
    running = 0
    for idx in indices:
        running = (running + shell[idx] // div) % 256
        key.append(running)

    if check_key(key, f"running_sum_div{div}"):
        exit()

    # Running XOR
    key = []
    running = 0
    for idx in indices:
        running = (running ^ (shell[idx] // div)) % 256
        key.append(running)

    if check_key(key, f"running_xor_div{div}"):
        exit()

# ============================================================================
# 13. Apply 17 at specific byte positions based on digit sequence
# ============================================================================
print("\n[13] Digit-selected multiplier positions...")

for mult in [17, 7, 10]:
    for threshold in range(10):
        shell_m = shell.copy()

        # Multiply at positions where digit >= threshold
        for i in range(32):
            digit = all_digits[i % 16]
            if digit >= threshold:
                idx = indices[i]
                shell_m[idx] *= mult

        key = [shell_m[idx] // 7 % 256 for idx in indices]
        if check_key(key, f"digit_mult_{mult}_thresh{threshold}"):
            exit()

print("\n" + "="*70)
print("Step pattern exploration complete")
print("="*70)
