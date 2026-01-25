"""
THINK HARDER:

shell[39] / 7 = 119 = 0x77 EXACTLY
shell[57] / 7 = 40 = 0x28 EXACTLY

What if the key uses SINGLE rectangles, not pairs?
The mini-puzzle tells us WHICH 32 rectangles to use!

09111819 FIX 11122111

Could be read as:
- Positions: 0, 9, 11, 18, 19, 11, 12, 21, 11...
- Or two-digit: 09, 11, 18, 19, 11, 12, 21, 11

The "following non-consecutive" hint means we don't use consecutive rects!
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
print("SINGLE RECTANGLE APPROACH")
print("="*70)

# First, let's see which rectangles give useful values when divided by 7
print("\n[1] Rectangles that give key values when /7...")
for i in range(64):
    val = shell[i] // 7
    if val == 119 or val == 40 or val % 256 == 119 or val % 256 == 40:
        print(f"  shell[{i}] = {shell[i]}, /7 = {val}, mod 256 = {val % 256}")

# ============================================================================
# 2. The mini-puzzle digits might be rectangle indices
# ============================================================================
print("\n[2] Mini-puzzle as rectangle indices...")

# Two-digit interpretation: 09, 11, 18, 19, 11, 12, 21, 11
two_digit = [9, 11, 18, 19, 11, 12, 21, 11]
print(f"Two-digit indices: {two_digit}")

# Build a 32-byte key by repeating these indices
for div in [7, 10, 1]:
    indices = (two_digit * 4)[:32]
    pairs = [shell[idx] // div % 256 for idx in indices]
    print(f"  div{div}: {bytes(pairs[:8]).hex()}...")
    if check_key(pairs, f"two_digit_div{div}"):
        exit()

# ============================================================================
# 3. Cumulative indices from digits
# ============================================================================
print("\n[3] Cumulative indices...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

# Start at 57 (gives 0x28) and walk using digits
for start in [0, 39, 57]:
    for div in [7, 10]:
        indices = []
        pos = start
        for i in range(32):
            indices.append(pos)
            digit = all_digits[i % 16]
            pos = (pos + digit + 1) % 64  # +1 because 0 means next

        pairs = [shell[idx] // div % 256 for idx in indices]
        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        has_28 = [j for j,p in enumerate(pairs) if p==0x28]

        if has_77 or has_28:
            print(f"  Start {start} div{div}: 0x28 at {has_28}, 0x77 at {has_77}")
            if check_key(pairs, f"walk_{start}_div{div}"):
                exit()

# ============================================================================
# 4. What if "FIX" means we fix the index at 39?
# ============================================================================
print("\n[4] FIX as anchor point...")

# Every byte involves position 39
for div in [7, 10]:
    pairs = []
    for i in range(32):
        # Use position i and position 39
        val = (shell[i] + shell[39]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  i+39 div{div}: 0x77 at {has_77}")
    if check_key(pairs, f"anchor39_div{div}"):
        exit()

# ============================================================================
# 5. The digit sequence as OFFSETS from 39
# ============================================================================
print("\n[5] Digits as offsets from FIX (39)...")

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        idx = (39 + digit + i) % 64
        val = shell[idx] // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    has_28 = [j for j,p in enumerate(pairs) if p==0x28]
    print(f"  39+digit+i div{div}: 0x28 at {has_28}, 0x77 at {has_77}")
    if check_key(pairs, f"offset39_div{div}"):
        exit()

# ============================================================================
# 6. Maybe we need shell[57] for byte 0, shell[39] for another position
# ============================================================================
print("\n[6] Specific positions for key bytes...")

# shell[57]/7 = 40 = 0x28 should be byte 0
# shell[39]/7 = 119 = 0x77 should be somewhere

for target_pos_77 in range(1, 32):
    pairs = []
    for i in range(32):
        if i == 0:
            idx = 57  # Gives 0x28
        elif i == target_pos_77:
            idx = 39  # Gives 0x77
        else:
            idx = i * 2  # Normal
        val = shell[idx] // 7 % 256
        pairs.append(val)

    if check_key(pairs, f"fixed_57_39_at_{target_pos_77}"):
        exit()

print("  No solution")

# ============================================================================
# 7. What if the digits tell us which VALUE to use, not index?
# ============================================================================
print("\n[7] Digits as value selectors...")

# Create pools of values
pools = {}
for div in [1, 7, 10, 17]:
    pools[div] = [shell[i] // div % 256 for i in range(64)]

# Use digit to select from pools
for base_pool in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        # Select index based on digit pattern
        idx = (i * 2 + digit) % 64
        val = pools[base_pool][idx]
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  Pool {base_pool}: 0x77 at {has_77}")
    if check_key(pairs, f"pool_{base_pool}"):
        exit()

# ============================================================================
# 8. Interleaved sequences
# ============================================================================
print("\n[8] Interleaved sequences...")

# First half from seq1 pattern, second half from seq2
for div in [7, 10]:
    pairs = []
    for i in range(32):
        if i < 16:
            digit = seq1[i % 8]
        else:
            digit = seq2[(i-16) % 8]
        idx = (i + digit) % 64
        val = shell[idx] // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  Interleaved div{div}: 0x77 at {has_77}")
    if check_key(pairs, f"interleaved_div{div}"):
        exit()

# ============================================================================
# 9. The 17 might not be a multiplier but an INDEX offset
# ============================================================================
print("\n[9] 17 as index offset...")

for div in [7, 10]:
    pairs = []
    for i in range(32):
        # Use i and i+17 (mod 64)
        idx1 = i
        idx2 = (i + 17) % 64
        val = (shell[idx1] + shell[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    has_28 = [j for j,p in enumerate(pairs) if p==0x28]
    print(f"  i+(i+17) div{div}: 0x28 at {has_28}, 0x77 at {has_77}")
    if check_key(pairs, f"offset17_div{div}"):
        exit()

# ============================================================================
# 10. XOR between shell[i] and shell[39]
# ============================================================================
print("\n[10] XOR with shell[39]...")

for div in [1, 7, 10]:
    pairs = []
    for i in range(32):
        val = (shell[i] ^ shell[39]) // div % 256 if div > 1 else (shell[i] ^ shell[39]) % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  XOR 39 div{div}: 0x77 at {has_77}")
    if check_key(pairs, f"xor39_div{div}"):
        exit()

# ============================================================================
# 11. Formula: shell[i] * 17 / 7 (the reverse)
# ============================================================================
print("\n[11] Multiply by 17 then divide...")

for i in range(64):
    val = shell[i] * 17 // 7 % 256
    if val == 0x77 or val == 0x28:
        print(f"  shell[{i}] * 17 / 7 = {val} ({hex(val)})")

# Build key with this formula
pairs = [shell[i] * 17 // 7 % 256 for i in range(32)]
print(f"  Key: {bytes(pairs[:8]).hex()}...")
if check_key(pairs, "mult17_div7"):
    exit()

# ============================================================================
# 12. Maybe the solution uses a completely different set of 32 rects
# ============================================================================
print("\n[12] Different rectangle selections...")

# What if we use rects 32-63 instead of 0-31?
for div in [7, 10]:
    pairs = [shell[32 + i] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Rects 32-63 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"rects32_63_div{div}"):
            exit()

# Odd-indexed rectangles
for div in [7, 10]:
    pairs = [shell[i*2 + 1] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Odd rects div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"odd_rects_div{div}"):
            exit()

# ============================================================================
# 13. The "following" might mean a linked list pattern
# ============================================================================
print("\n[13] Linked list pattern (value-based following)...")

for div in [7, 10]:
    pairs = []
    idx = 0  # Start
    visited = set()
    for i in range(32):
        while idx in visited:
            idx = (idx + 1) % 64
        visited.add(idx)
        val = shell[idx] // div % 256
        pairs.append(val)
        # Next index is based on current value
        idx = shell[idx] % 64

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Linked div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"linked_div{div}"):
            exit()

# ============================================================================
# 14. Systematic single-rect search with all starting points and patterns
# ============================================================================
print("\n[14] Systematic single-rect patterns...")

for start in range(64):
    for step in range(1, 64):
        if step == 1:  # Skip consecutive
            continue

        for div in [7, 10]:
            indices = [(start + i * step) % 64 for i in range(32)]
            pairs = [shell[idx] // div % 256 for idx in indices]

            if pairs[0] == 0x28 and 0x77 in pairs:
                has_77 = [j for j,p in enumerate(pairs) if p==0x77]
                print(f"  Start {start} step {step} div{div}: 0x77 at {has_77}")
                if check_key(pairs, f"sys_{start}_{step}_div{div}"):
                    exit()

print("  No solution with systematic patterns")

print("\n" + "="*70)
print("Single rectangle approach complete")
print("="*70)
