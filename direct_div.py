"""
Direct division approach:
shell[39] = 839, and 839/7 = 119.857 ~ 119 = 0x77!

What if individual shell values, when divided by 7, give us bytes directly?
No pairing needed?
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
print("DIRECT DIVISION EXPLORATION")
print("="*70)

# ============================================================================
# 1. Check which shell values give 0x77 when divided by 7
# ============================================================================
print("\n[1] Shell values that give 119 (0x77) when divided by 7...")

for i, s in enumerate(shell):
    if s // 7 == 119:
        print(f"  shell[{i}] = {s}, {s}/7 = {s//7}")
    if s // 7 % 256 == 119:
        print(f"  shell[{i}] = {s}, {s}/7 mod 256 = {s//7 % 256}")

# ============================================================================
# 2. Check which give 0x28 = 40 when divided by various values
# ============================================================================
print("\n[2] Shell values that give 40 (0x28) when divided...")

for div in [7, 10, 30, 64]:
    print(f"  Div by {div}:")
    for i, s in enumerate(shell):
        if s // div % 256 == 40:
            print(f"    shell[{i}] = {s}, {s}/{div} = {s//div} (mod 256 = {s//div % 256})")

# ============================================================================
# 3. Try using single shell values (no pairing) for 32 bytes
# ============================================================================
print("\n[3] Single shell values, select 32 of 64...")

# First 32
for div in [7, 10]:
    pairs = [shell[i] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  First 32 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"first32_single_div{div}"):
            exit()

# Every other shell
for div in [7, 10]:
    pairs = [shell[i*2] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Even shells div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"even_single_div{div}"):
            exit()

# Specific 32 based on digit sequence pattern
seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

# Use digits to select which shells
for div in [7, 10]:
    pairs = []
    idx = 0
    for i in range(32):
        digit = all_digits[i % 16]
        step = digit if digit > 0 else 1
        pairs.append(shell[idx % 64] // div % 256)
        idx += step

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Digit-stepped single div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"digit_stepped_single_div{div}"):
            exit()

# ============================================================================
# 4. What if we need to multiply rect 39 THEN take individual values?
# ============================================================================
print("\n[4] Single shells with mult at 39...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10, 17]:
    pairs = [shell_m[i*2] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Even shells m17 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"even_single_m17_div{div}"):
            exit()

# ============================================================================
# 5. What about shell[39] * 17 / 119 = 119.something?
#    839 * 17 = 14263, 14263 / 119 = 119.86...
# ============================================================================
print("\n[5] Division by 119...")

shell_m = shell.copy()
shell_m[39] *= 17

for i in range(64):
    if shell_m[i] // 119 % 256 == 119:
        print(f"  shell_m[{i}] / 119 = 119: value = {shell_m[i]}")

# ============================================================================
# 6. What if the sum of all digit values is the key divisor?
#    30 + 10 = 40
# ============================================================================
print("\n[6] Division by 40 (digit sum total)...")

shell_m = shell.copy()
shell_m[39] *= 17

for offset in [0, 1]:
    pairs = []
    for i in range(32):
        val = (shell_m[i*2 + offset] + shell_m[(i*2 + offset + 1) % 64]) // 40 % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Pairs offset {offset} div 40: 0x77 at {has_77}")
        if check_key(pairs, f"pairs_offset{offset}_div40"):
            exit()

# ============================================================================
# 7. What if we need to XOR consecutive bytes?
# ============================================================================
print("\n[7] XOR between consecutive shell values...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [1, 7, 10]:
    pairs = []
    for i in range(32):
        a = shell_m[i*2] // div % 256
        b = shell_m[i*2 + 1] // div % 256
        pairs.append(a ^ b)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  XOR consecutive div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"xor_consec_div{div}"):
            exit()

# ============================================================================
# 8. What if position 19 in the key must be 0x77?
#    And we need to find what makes that happen?
# ============================================================================
print("\n[8] Analyzing position 19...")

# With standard formula (pairs, div7, m17), position 19 already has 0x77
# Let's see what pair of rects gives us position 19

print("  Position 19 comes from rects 38 and 39 (or with skip from different rects)")
print(f"  shell[38] = {shell[38]}, shell[39] = {shell[39]}")
print(f"  shell[38] + shell[39] = {shell[38] + shell[39]}")
print(f"  (shell[38] + shell[39]*17) / 7 = {(shell[38] + shell[39]*17) // 7}")
print(f"  That mod 256 = {(shell[38] + shell[39]*17) // 7 % 256}")

# So (912 + 839*17) / 7 % 256 = (912 + 14263) / 7 % 256 = 15175 / 7 % 256 = 2167 % 256 = 119 = 0x77!
# This confirms the calculation is correct.

# ============================================================================
# 9. Maybe we need both 0x28 at position 0 AND 0x77 at position 19
#    Let's verify our base key has both
# ============================================================================
print("\n[9] Verifying base key properties...")

shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    base.append(val)

print(f"  Base[0] = {hex(base[0])} (should be 0x28)")
print(f"  Base[19] = {hex(base[19])} (should be 0x77)")
print(f"  Full key: {bytes(base).hex()}")

# ============================================================================
# 10. What if we need to divide by different values for different halves?
#     First 16 bytes / 7, last 16 bytes / 10
# ============================================================================
print("\n[10] Split divisors again with variations...")

shell_m = shell.copy()
shell_m[39] *= 17

# Try all split points
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

            # Check if this gives right pattern
            if pairs[0] == 0x28 and 0x77 in pairs:
                pos_77 = [j for j,p in enumerate(pairs) if p==0x77]
                # Only print if 0x77 is at a position related to 19 or other hints
                if 19 in pos_77 or 17 in pos_77 or 7 in pos_77:
                    print(f"  Split at {split}, d1={d1}, d2={d2}: 0x77 at {pos_77}")
                    if check_key(pairs, f"split{split}_d{d1}_{d2}"):
                        exit()

# ============================================================================
# 11. What if the 8-digit sequence tells us the divisor for each pair?
#     0->10, 9->9, 1->1, etc.
# ============================================================================
print("\n[11] Per-pair divisor from digits...")

shell_m = shell.copy()
shell_m[39] *= 17

# Digits as divisors (0 becomes 10)
pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    div = digit if digit > 0 else 10
    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
    pairs.append(val)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
if has_77:
    print(f"  Digit as divisor: first={hex(pairs[0])}, 0x77 at {has_77}")
    if check_key(pairs, "digit_as_divisor"):
        exit()

# Digits + 6 as divisors (6 is from FIX = F = 6th letter)
pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    div = digit + 6
    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
    pairs.append(val)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
if has_77:
    print(f"  Digit+6 as divisor: first={hex(pairs[0])}, 0x77 at {has_77}")
    if check_key(pairs, "digit_plus6_div"):
        exit()

# ============================================================================
# 12. Brute force: try modifying 3 bytes at once
#     Focus on positions that might be significant
# ============================================================================
print("\n[12] Three-byte modification at key positions...")

key_pos = [0, 7, 17, 19]  # 0, 7 (div), 17 (mult), 19 (has 0x77)

count = 0
for p1 in key_pos:
    for p2 in key_pos:
        for p3 in key_pos:
            if p1 >= p2 or p2 >= p3:
                continue
            # Try a smaller set of values
            for v1 in range(0, 256, 16):
                for v2 in range(0, 256, 16):
                    for v3 in range(0, 256, 16):
                        pairs = base.copy()
                        pairs[p1] = v1
                        pairs[p2] = v2
                        pairs[p3] = v3
                        if check_key(pairs, f"3byte_{p1}_{p2}_{p3}"):
                            exit()
                        count += 1

print(f"  Checked {count} three-byte modifications: no solution")

print("\n" + "="*70)
print("Direct division exploration complete")
print("="*70)
