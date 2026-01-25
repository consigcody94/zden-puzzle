"""
BREAKTHROUGH INSIGHT:
- shell[39] / 7 = 119 = 0x77 EXACTLY
- shell[57] / 7 = 40 = 0x28 EXACTLY
- 57 - 39 = 18, and "18" appears in 09111819!

The digit sequence might tell us WHICH rectangles to use!
09, 11, 18, 19 might be offsets from base position 39?

39 + 0 = 39 -> gives 0x77
39 + 18 = 57 -> gives 0x28

What about 39 + 9 = 48, 39 + 11 = 50, 39 + 19 = 58?
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

print("="*70)
print("INDEX PATTERN EXPLORATION")
print("="*70)

# ============================================================================
# 1. Check shell values at key offsets from 39
# ============================================================================
print("\n[1] Shell values at offsets from 39...")

offsets_from_digits = [0, 9, 11, 18, 19, 11, 12, 21, 11]
for off in set(offsets_from_digits):
    idx = (39 + off) % 64
    print(f"  39 + {off} = {idx}: shell[{idx}] = {shell[idx]}, / 7 = {shell[idx] // 7}")

# ============================================================================
# 2. Parse 09111819 and 11122111 as two-digit numbers
# ============================================================================
print("\n[2] Two-digit number interpretation...")

# 09, 11, 18, 19 from first sequence
nums1 = [9, 11, 18, 19]
# 11, 12, 21, 11 from second sequence
nums2 = [11, 12, 21, 11]

all_nums = nums1 + nums2  # 8 numbers
print(f"Parsed numbers: {all_nums}")

# Use these as indices into shell
print("Shell values at these indices:")
for i, idx in enumerate(all_nums):
    print(f"  shell[{idx}] = {shell[idx]}, / 7 = {shell[idx] // 7} (mod 256 = {shell[idx] // 7 % 256})")

# ============================================================================
# 3. Try using these indices to build the key
# ============================================================================
print("\n[3] Building key from parsed indices...")

# We have 8 indices but need 32 bytes
# Maybe each index gives us 4 bytes?

for div in [7, 10]:
    # Method 1: Repeat the 8 indices 4 times
    indices = all_nums * 4
    pairs = [shell[idx] // div % 256 for idx in indices]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Repeat x4 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"repeat4_div{div}"):
            exit()

    # Method 2: Use index as offset from position
    pairs = []
    for i in range(32):
        offset = all_nums[i % 8]
        idx = (i + offset) % 64
        pairs.append(shell[idx] // div % 256)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Offset method div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"offset_method_div{div}"):
            exit()

# ============================================================================
# 4. Maybe the digits are read differently: 0, 9, 1, 11, 8, 19 (alternating 1-2 digits)
# ============================================================================
print("\n[4] Alternative digit groupings...")

# Try: 0, 9, 11, 18, 19 (variable length based on context)
alt_groups = [
    [0, 9, 1, 1, 1, 8, 1, 9],  # Original
    [0, 9, 11, 18, 19],        # Two-digit where possible
    [9, 11, 18, 19],           # Skip leading 0
    [0, 91, 1, 18, 19],        # Different grouping
]

for group in alt_groups:
    print(f"  Trying group: {group}")

    if len(group) < 32:
        # Use as indices
        indices = (group * 10)[:32]  # Repeat to get 32
        for div in [7, 10]:
            pairs = [shell[idx % 64] // div % 256 for idx in indices]
            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            if has_77:
                print(f"    Indices div{div}: 0x77 at {has_77}")
                if check_key(pairs, f"alt_group_div{div}"):
                    exit()

# ============================================================================
# 5. What if we need to use both sequences to compute each byte?
#    seq1 digit -> index1, seq2 digit -> index2, combine
# ============================================================================
print("\n[5] Two-sequence combination...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]

for div in [7, 10]:
    pairs = []
    for i in range(32):
        d1 = seq1[i % 8]
        d2 = seq2[i % 8]

        # Combine: d1 is tens, d2 is ones (like 09, 11, etc.)
        idx = (d1 * 10 + d2) % 64
        pairs.append(shell[idx] // div % 256)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  d1*10+d2 as index div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"d1_10_d2_idx_div{div}"):
            exit()

# ============================================================================
# 6. What if FIX=39 is the base, and digits are offsets?
# ============================================================================
print("\n[6] FIX (39) as base with digit offsets...")

for div in [7, 10]:
    pairs = []
    base = 39

    for i in range(32):
        digit = (seq1 + seq2)[i % 16]
        idx = (base + digit + i) % 64  # Add position too
        pairs.append(shell[idx] // div % 256)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Base 39 + digit + i div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"base39_offset_div{div}"):
            exit()

# ============================================================================
# 7. The "18" in sequence might mean: distance from 39 to 57 is 18
#    Use this to generate offset pattern
# ============================================================================
print("\n[7] Distance-based pattern...")

# From 39: +0=39 (0x77), +18=57 (0x28)
# Generate 32 indices based on sequence

all_digits = seq1 + seq2  # [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

for div in [7, 10]:
    pairs = []
    pos = 39
    for i in range(32):
        digit = all_digits[i % 16]
        pairs.append(shell[pos] // div % 256)
        pos = (pos + digit) % 64

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Walk from 39 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"walk39_div{div}"):
            exit()

# Start from 57 (which gives 0x28)
for div in [7, 10]:
    pairs = []
    pos = 57
    for i in range(32):
        digit = all_digits[i % 16]
        pairs.append(shell[pos] // div % 256)
        pos = (pos + digit) % 64

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Walk from 57 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"walk57_div{div}"):
            exit()

# ============================================================================
# 8. Maybe we need pairs of shell values using the distance pattern
# ============================================================================
print("\n[8] Pairing with distance pattern...")

# 18 is the key distance
for div in [7, 10]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        idx2 = (idx1 + 18) % 64  # Use 18 as the pairing distance
        val = (shell[idx1] + shell[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Distance 18 pairing div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"dist18_div{div}"):
            exit()

# Try other distances from the digits
for dist in [9, 11, 18, 19, 21]:
    for div in [7, 10]:
        pairs = []
        for i in range(32):
            idx1 = i * 2
            idx2 = (idx1 + dist) % 64
            val = (shell[idx1] + shell[idx2]) // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77 and pairs[0] == 0x28:
            print(f"  Distance {dist} pairing div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
            if check_key(pairs, f"dist{dist}_div{div}"):
                exit()

# ============================================================================
# 9. What if 39 and 57 are both multiplied?
# ============================================================================
print("\n[9] Multiplying at both 39 and 57...")

for m39 in [1, 7, 17]:
    for m57 in [1, 7, 17]:
        if m39 == 1 and m57 == 1:
            continue

        shell_m = shell.copy()
        shell_m[39] *= m39
        shell_m[57] *= m57

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if pairs[0] == 0x28 and 0x77 in pairs:
                pos_77 = [j for j,p in enumerate(pairs) if p==0x77]
                print(f"  m39={m39}, m57={m57}, div{div}: first={hex(pairs[0])}, 0x77 at {pos_77}")
                if check_key(pairs, f"m39_{m39}_m57_{m57}_div{div}"):
                    exit()

# ============================================================================
# 10. Shell[57]/7 = 40, but maybe we need to place it at position 0?
# ============================================================================
print("\n[10] Reordering to put 0x28 from shell[57] at position 0...")

# Currently position 0 comes from shell[0] + shell[1]
# We want shell[57] to contribute to position 0

shell_m = shell.copy()
shell_m[39] *= 17

# What if we start from rect 57?
for div in [7, 10]:
    pairs = []
    for i in range(32):
        idx1 = (57 + i*2) % 64
        idx2 = (57 + i*2 + 1) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Start from 57 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"start57_div{div}"):
            exit()

# ============================================================================
# 11. What if the formula uses shell[57] explicitly for byte 0?
# ============================================================================
print("\n[11] Explicit position mapping...")

shell_m = shell.copy()
shell_m[39] *= 17

# Byte 0 = shell[57] / 7
# Byte 19 = (shell[38] + shell[39]*17) / 7 = 0x77 (we know this works)
# What about other bytes?

print(f"  shell[57] / 7 = {shell[57] // 7} = {hex(shell[57] // 7)}")

# Build key with shell[57] at position 0
pairs = [shell[57] // 7 % 256]  # Byte 0 = 0x28

# Fill rest with standard formula
for i in range(1, 32):
    val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    pairs.append(val)

print(f"  Key with shell[57] at pos 0: first={hex(pairs[0])}, 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
if check_key(pairs, "shell57_pos0"):
    exit()

# ============================================================================
# 12. What if single shells (not pairs) give us the key?
#     Using only specific indices
# ============================================================================
print("\n[12] Single shell selection based on digit pattern...")

# Build index list: start at 57 (gives 0x28), then follow pattern
indices = []
pos = 57
for i in range(32):
    indices.append(pos)
    digit = (seq1 + seq2)[i % 16]
    pos = (pos + digit) % 64

for div in [7, 10]:
    pairs = [shell[idx] // div % 256 for idx in indices]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  Walk from 57 single div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
    if check_key(pairs, f"walk57_single_div{div}"):
        exit()

# Start at 39 (gives 0x77)
indices = []
pos = 39
for i in range(32):
    indices.append(pos)
    digit = (seq1 + seq2)[i % 16]
    pos = (pos + digit) % 64

for div in [7, 10]:
    pairs = [shell[idx] // div % 256 for idx in indices]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  Walk from 39 single div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
    if check_key(pairs, f"walk39_single_div{div}"):
        exit()

print("\n" + "="*70)
print("Index pattern exploration complete")
print("="*70)

# Show the indices visited when walking from 57
print("\nIndices when walking from 57:")
pos = 57
for i in range(32):
    digit = (seq1 + seq2)[i % 16]
    print(f"  Byte {i}: shell[{pos}] = {shell[pos]}, /7 = {shell[pos]//7}")
    pos = (pos + digit) % 64
