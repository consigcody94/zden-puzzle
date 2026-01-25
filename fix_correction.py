"""
Think harder about the puzzle:
- 09111819 FIX 11122111
- FIX = 39 (F=6, I=9, X=24)
- Digit sums: 30 + 10 = 40 = 0x28

What if the second sequence FIXES the first?
0->1 (add 1)
9->1 (subtract 8, or mod 10 -> 9+1+1=11%10=1?)
1->1 (same)
1->2 (add 1)
1->2 (add 1)
8->1 (subtract 7, or 8+1+1+1=11%10=1?)
1->1 (same)
9->1 (subtract 8)

Let's try: apply both sequences in different ways.
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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # sum = 30
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # sum = 10

# Correction values: how seq2 "fixes" seq1
correction = [seq2[i] - seq1[i] for i in range(8)]
print(f"Correction values: {correction}")  # [1, -8, 0, 1, 1, -7, 0, -8]

print("="*70)
print("FIX CORRECTION EXPLORATION")
print("="*70)

# ============================================================================
# 1. Use correction values to modify the base key
# ============================================================================
print("\n[1] Apply correction to base PairMatch key...")

def get_skip(digit):
    if digit == 0:
        return 1
    return digit

all_digits = seq1 + seq2

shell_m = shell.copy()
shell_m[39] *= 17

# Base key
base = []
for i in range(32):
    digit = all_digits[i % 16]
    skip = get_skip(digit)
    idx1 = i * 2
    idx2 = (i * 2 + skip) % 64
    val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    base.append(val)

print(f"Base: {bytes(base).hex()}")
print(f"First: {hex(base[0])}, 0x77 at: {[i for i,b in enumerate(base) if b==0x77]}")

# Apply correction as byte offset
for mult in [1, 7, 10, 17]:
    pairs = []
    for i in range(32):
        corr = correction[i % 8]
        pairs.append((base[i] + corr * mult) % 256)
    if check_key(pairs, f"correction_mult{mult}"):
        exit()

# ============================================================================
# 2. What if seq2 is the REAL sequence and seq1 tells us what to subtract?
# ============================================================================
print("\n[2] Use seq2 for skip, seq1 as adjustment...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        # Use seq2 for the skip pattern (it's the "fixed" version)
        digit2 = seq2[i % 8]
        skip = digit2 if digit2 > 0 else 1

        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64

        # Use seq1 as adjustment
        digit1 = seq1[i % 8]

        val = (shell_m[idx1] + shell_m[idx2] - digit1) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Seq2 skip, seq1 adjust, div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"seq2_skip_seq1_adj_div{div}"):
            exit()

# ============================================================================
# 3. The digits might represent bit positions to XOR
# ============================================================================
print("\n[3] Digits as bit positions to XOR...")

for mask_seq in [seq1, seq2, seq1 + seq2]:
    pairs = []
    for i in range(32):
        digit = mask_seq[i % len(mask_seq)]
        xor_mask = 1 << digit if digit < 8 else 0
        pairs.append(base[i] ^ xor_mask)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        if check_key(pairs, f"xor_bit_{len(mask_seq)}"):
            exit()

# ============================================================================
# 4. Maybe each digit pair (before/after FIX) encodes one byte's operation
# ============================================================================
print("\n[4] Digit pairs as operations...")

# For byte i: use seq1[i%8] and seq2[i%8] together
for div in [7, 10]:
    pairs = []
    for i in range(32):
        d1 = seq1[i % 8]  # Before FIX
        d2 = seq2[i % 8]  # After FIX

        idx1 = i * 2
        idx2 = (i * 2 + d1) % 64 if d1 > 0 else (i * 2 + 1) % 64

        # Multiply by d2
        val = (shell_m[idx1] + shell_m[idx2]) * d2 // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Skip by d1, mult by d2, div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"d1_skip_d2_mult_div{div}"):
            exit()

# ============================================================================
# 5. What if 09111819 is a date? 09/11/1819 or 1/8/1919?
#    Or a simple encoding: take digits as nibbles
# ============================================================================
print("\n[5] Digit sequences as nibble values...")

# Combine pairs of digits into bytes
nibble_bytes1 = []
for i in range(0, 8, 2):
    nibble_bytes1.append(seq1[i] * 16 + seq1[i+1])
print(f"Seq1 as nibbles: {[hex(b) for b in nibble_bytes1]}")  # [0x09, 0x11, 0x18, 0x19]

nibble_bytes2 = []
for i in range(0, 8, 2):
    nibble_bytes2.append(seq2[i] * 16 + seq2[i+1])
print(f"Seq2 as nibbles: {[hex(b) for b in nibble_bytes2]}")  # [0x11, 0x12, 0x21, 0x11]

# XOR base with these patterns
for xor_pattern in [nibble_bytes1, nibble_bytes2]:
    pairs = []
    for i in range(32):
        xor_val = xor_pattern[i % 4]
        pairs.append(base[i] ^ xor_val)
    if check_key(pairs, f"xor_nibble_{xor_pattern[0]:02x}"):
        exit()

# ============================================================================
# 6. What if the second sequence tells us which rect to use from the first?
#    seq1 = indices, seq2 = selection pattern
# ============================================================================
print("\n[6] Seq1 as rect offsets, seq2 as selection...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        d1 = seq1[i % 8]  # Offset
        d2 = seq2[i % 8]  # Selection multiplier

        # Base index + offset from d1
        idx = (i + d1) % 64

        # Value = shell[idx] * d2
        val = shell_m[idx] * d2 // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  d1 offset, d2 mult, div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"d1_offset_d2_mult_div{div}"):
            exit()

# ============================================================================
# 7. Maybe the "non-consecutive" hint means interleaved sequences
# ============================================================================
print("\n[7] Interleaved byte extraction...")

# Interleave seq1 and seq2 to get 16 values
interleaved = []
for i in range(8):
    interleaved.append(seq1[i])
    interleaved.append(seq2[i])
print(f"Interleaved: {interleaved}")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = interleaved[i % 16]
        skip = digit if digit > 0 else 1
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Interleaved div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"interleaved_div{div}"):
            exit()

# ============================================================================
# 8. The 8-digit sequences might define 8 bytes, not 32
#    Each digit tells us which formula to use for that byte
# ============================================================================
print("\n[8] 8-digit -> 8-byte pattern, then repeat or expand...")

shell_m = shell.copy()
shell_m[39] *= 17

# Generate 8 bytes based on digits, then expand to 32
for div in [7, 10]:
    base8 = []
    for i in range(8):
        d1 = seq1[i]
        d2 = seq2[i]

        # Use 4 rects per byte (8*4=32 pairs, 32*2=64 rects)
        idx_base = i * 8
        val = 0
        for j in range(4):
            idx1 = (idx_base + j * 2) % 64
            idx2 = (idx_base + j * 2 + 1) % 64
            pair_val = (shell_m[idx1] + shell_m[idx2]) // div
            val = (val + pair_val) % 256
        base8.append(val)

    # Expand to 32 bytes by repeating
    pairs = base8 * 4
    if check_key(pairs, f"8byte_repeat_div{div}"):
        exit()

    # Or by using different expansion
    pairs = []
    for i in range(32):
        pairs.append((base8[i % 8] + i) % 256)
    if check_key(pairs, f"8byte_offset_div{div}"):
        exit()

# ============================================================================
# 9. What if 30 and 10 are offsets into the key?
#    Position 30 and position 10 might be special
# ============================================================================
print("\n[9] Position-based hints (30, 10)...")

print(f"  Base[10] = {hex(base[10])}, Base[30] = {hex(base[30])}")

# Swap positions 10 and 30
pairs = base.copy()
pairs[10], pairs[30] = pairs[30], pairs[10]
if check_key(pairs, "swap_10_30"):
    exit()

# Set position 10 to 30, position 30 to 10
pairs = base.copy()
pairs[10] = 30
pairs[30] = 10
if check_key(pairs, "set_10_30"):
    exit()

# ============================================================================
# 10. Try outer + inner instead of shell (shell = outer - inner)
# ============================================================================
print("\n[10] Using outer + inner instead of shell...")

outer_m = outer.copy()
outer_m[39] *= 17
inner_m = inner.copy()
inner_m[39] *= 17

combined = [outer_m[i] + inner_m[i] for i in range(64)]

for div in [7, 10, 17, 64]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (combined[idx1] + combined[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Outer+Inner div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"outer_inner_div{div}"):
            exit()

# ============================================================================
# 11. What about outer * inner?
# ============================================================================
print("\n[11] Using outer * inner...")

product = [outer[i] * inner[i] for i in range(64)]

for div in [10000, 100000, 1000000]:
    pairs = []
    for i in range(32):
        val = (product[i * 2] + product[i * 2 + 1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Outer*Inner div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"product_div{div}"):
            exit()

# ============================================================================
# 12. Maybe use inner/outer ratio?
# ============================================================================
print("\n[12] Using inner/outer ratio...")

for scale in [100, 256, 1000]:
    pairs = []
    for i in range(32):
        idx = i * 2
        ratio1 = inner[idx] * scale // outer[idx] if outer[idx] > 0 else 0
        ratio2 = inner[idx+1] * scale // outer[idx+1] if outer[idx+1] > 0 else 0
        val = (ratio1 + ratio2) // 2 % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Inner/Outer scale{scale}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"ratio_scale{scale}"):
            exit()

# ============================================================================
# 13. Focus on making 0x77 appear at the RIGHT position
#     The address starts with "1crypto" - maybe position matters
# ============================================================================
print("\n[13] Trying to align 0x77 to different positions...")

# We have 0x77 at position 19 in base key
# Try shifting the key
for shift in range(32):
    pairs = base[shift:] + base[:shift]
    if check_key(pairs, f"shift_{shift}"):
        exit()

# ============================================================================
# 14. What if we need to hash the key first?
# ============================================================================
print("\n[14] Hash transformations...")

# SHA256 of base
hashed = hashlib.sha256(bytes(base)).digest()
if check_key(list(hashed), "sha256_of_base"):
    exit()

# Double SHA256
double_hashed = hashlib.sha256(hashed).digest()
if check_key(list(double_hashed), "double_sha256"):
    exit()

# RIPEMD160
ripe = hashlib.new('ripemd160')
ripe.update(bytes(base))
# Only 20 bytes, pad to 32
ripe_digest = ripe.digest()
padded = list(ripe_digest) + [0] * 12
if check_key(padded, "ripemd160_padded"):
    exit()

print("\n" + "="*70)
print("No solution found in this batch.")
print("="*70)

# Print the best candidate again
print(f"\nBest candidate still:")
print(f"Hex: {bytes(base).hex()}")
print(f"First byte: {hex(base[0])} (0x28 = 40 = digit sum)")
print(f"0x77 at position: {[i for i,b in enumerate(base) if b==0x77]}")
