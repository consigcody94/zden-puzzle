"""
Interesting finding: using digit parity to select between div7 and div10
gives first byte 0x28!

Let's explore variations of this approach.
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
print("PARITY-BASED DIVISOR SELECTION")
print("="*70)

# ============================================================================
# 1. Reproduce the finding and verify
# ============================================================================
print("\n[1] Reproducing parity selection...")

shell_m = shell.copy()
shell_m[39] *= 17

# Two pools
pool7 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
pool10 = [(shell_m[i*2] + shell_m[i*2+1]) // 10 % 256 for i in range(32)]

print(f"Pool7[0] = {hex(pool7[0])}, Pool10[0] = {hex(pool10[0])}")
print(f"Pool7[19] = {hex(pool7[19])}, Pool10[19] = {hex(pool10[19])}")

# Digit at position 0 is 0 (even) -> pool7
# Expected first byte = pool7[0] = 0x28
pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    if digit % 2 == 0:
        pairs.append(pool7[i])
    else:
        pairs.append(pool10[i])

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"Parity selection: first={hex(pairs[0])}, 0x77 at {has_77}")
print(f"Key: {bytes(pairs).hex()}")

# Check which positions use which divisor
print("\nDivisor pattern by digit parity:")
for i in range(16):
    digit = all_digits[i]
    div = 7 if digit % 2 == 0 else 10
    print(f"  Position {i:2d}: digit={digit}, div={div}")

if check_key(pairs, "parity_selection"):
    exit()

# ============================================================================
# 2. Now we need to also get 0x77 somewhere
#    With parity selection, byte 19 uses digit seq2[3]=2 (even) -> pool7[19]=0x77!
# ============================================================================
print("\n[2] Checking byte 19...")

# Digit at position 19 is seq2[3] = 2 (even)
# So it uses pool7[19]
print(f"Position 19: digit index = 19 % 16 = 3, seq2[3] = {seq2[3]}")
print(f"seq2[3] = {seq2[3]} is even, so uses pool7")
print(f"pool7[19] = {hex(pool7[19])}")

# Wait, pool7[19] should be 0x77 based on our earlier calculation!
# Let me verify

val = (shell_m[19*2] + shell_m[19*2+1]) // 7 % 256
print(f"Calculated: (shell_m[38] + shell_m[39]) / 7 % 256 = {val} = {hex(val)}")

# Hmm, this should be 0x77. Let me check the pool calculation again.

# ============================================================================
# 3. The issue: position 19 uses rects 38 and 39 in pairs mode
#    But we multiplied shell[39] by 17!
# ============================================================================
print("\n[3] Verifying calculation...")

print(f"shell[38] = {shell[38]}, shell[39] = {shell[39]}")
print(f"shell_m[38] = {shell_m[38]}, shell_m[39] = {shell_m[39]}")
print(f"(shell_m[38] + shell_m[39]) / 7 = {(shell_m[38] + shell_m[39]) // 7}")
print(f"That mod 256 = {(shell_m[38] + shell_m[39]) // 7 % 256}")

# So pool7[19] = (912 + 839*17) / 7 % 256 = (912 + 14263) / 7 % 256 = 15175/7 % 256 = 2167 % 256 = 119 = 0x77

# But wait, in the parity selection the digit at position 19 (which is 19 % 16 = 3)
# is seq2[3] = 2, which is EVEN, so it should use pool7!

# Let me recalculate the parity selection
print("\n[4] Recalculating with correct parity...")

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    if digit % 2 == 0:
        pairs.append(pool7[i])
    else:
        pairs.append(pool10[i])

print(f"Byte 19: digit index = {19 % 16}, digit = {all_digits[19 % 16]}")
print(f"Digit {all_digits[19 % 16]} is {'even' if all_digits[19 % 16] % 2 == 0 else 'odd'}")
print(f"Using pool{'7' if all_digits[19 % 16] % 2 == 0 else '10'}")
print(f"Value = {hex(pairs[19])}")

# ============================================================================
# 4. The digit at position 19 (index 3 in repeating 16) is seq2[3] = 2
#    2 is even, so we use pool7[19] which is 0x77!
# ============================================================================

# But the earlier output showed "0x77 at []" meaning no 0x77 was found
# Let me check if pool7[19] is indeed 0x77

print(f"\npool7[19] = {pool7[19]} = {hex(pool7[19])}")

# Hmm, if pool7 was calculated correctly it should be 0x77 at position 19
# Let me recalculate

for i in range(32):
    val7 = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    if val7 == 0x77:
        print(f"pool7[{i}] = 0x77")

# ============================================================================
# 5. Maybe the issue is in how we're calculating the pools
#    Let me trace through step by step
# ============================================================================
print("\n[5] Step by step pool calculation...")

# For position 19:
i = 19
idx1 = i * 2  # = 38
idx2 = i * 2 + 1  # = 39

print(f"Position {i}: idx1={idx1}, idx2={idx2}")
print(f"shell[{idx1}] = {shell[idx1]}, shell[{idx2}] = {shell[idx2]}")
print(f"shell_m[{idx1}] = {shell_m[idx1]}, shell_m[{idx2}] = {shell_m[idx2]}")
print(f"Sum = {shell_m[idx1] + shell_m[idx2]}")
print(f"Sum / 7 = {(shell_m[idx1] + shell_m[idx2]) // 7}")
print(f"Mod 256 = {(shell_m[idx1] + shell_m[idx2]) // 7 % 256}")

# So pool7[19] SHOULD be 0x77!

# ============================================================================
# 6. Let me verify the entire key calculation
# ============================================================================
print("\n[6] Full key with parity selection...")

shell_m = shell.copy()
shell_m[39] *= 17

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1

    if digit % 2 == 0:  # Even digit -> div 7
        val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    else:  # Odd digit -> div 10
        val = (shell_m[idx1] + shell_m[idx2]) // 10 % 256

    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at positions: {has_77}")
print(f"Key: {bytes(pairs).hex()}")

if check_key(pairs, "parity_div_selection"):
    exit()

# ============================================================================
# 7. Try swapping: odd -> div7, even -> div10
# ============================================================================
print("\n[7] Swapped parity: odd->div7, even->div10...")

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1

    if digit % 2 == 1:  # Odd digit -> div 7
        val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    else:  # Even digit -> div 10
        val = (shell_m[idx1] + shell_m[idx2]) // 10 % 256

    pairs.append(val)

print(f"First byte: {hex(pairs[0])}")
print(f"Byte 19: {hex(pairs[19])}")
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"0x77 at positions: {has_77}")

if check_key(pairs, "swapped_parity"):
    exit()

# ============================================================================
# 8. Single byte modification on the parity-selected key
# ============================================================================
print("\n[8] Single byte modification on parity key...")

# Use the key with parity selection
shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1
    if digit % 2 == 0:
        val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    else:
        val = (shell_m[idx1] + shell_m[idx2]) // 10 % 256
    base.append(val)

for pos in range(32):
    for val in range(256):
        pairs = base.copy()
        pairs[pos] = val
        if check_key(pairs, f"parity_mod_p{pos}_v{val}"):
            exit()

print("  Single byte mod: no solution")

# ============================================================================
# 9. Try different divisor pairs
# ============================================================================
print("\n[9] Different divisor pairs with parity...")

for d1 in [7, 10, 17, 30]:
    for d2 in [7, 10, 17, 30]:
        if d1 == d2:
            continue

        pairs = []
        for i in range(32):
            digit = all_digits[i % 16]
            idx1 = i * 2
            idx2 = i * 2 + 1
            if digit % 2 == 0:
                val = (shell_m[idx1] + shell_m[idx2]) // d1 % 256
            else:
                val = (shell_m[idx1] + shell_m[idx2]) // d2 % 256
            pairs.append(val)

        if pairs[0] == 0x28 and 0x77 in pairs:
            pos_77 = [j for j,p in enumerate(pairs) if p==0x77]
            print(f"  d1={d1}, d2={d2}: first={hex(pairs[0])}, 0x77 at {pos_77}")
            if check_key(pairs, f"parity_d{d1}_{d2}"):
                exit()

# ============================================================================
# 10. Try using digit VALUE (not just parity) to select divisor
# ============================================================================
print("\n[10] Digit value as divisor selector...")

for base_div in [1, 5, 7]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        idx1 = i * 2
        idx2 = i * 2 + 1
        div = digit + base_div if digit > 0 else base_div + 1
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  base_div={base_div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"digit_value_div_base{base_div}"):
            exit()

print("\n" + "="*70)
print("Parity exploration complete")
print("="*70)

# Show the best candidate
print("\nBest parity-based candidate:")
pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    idx1 = i * 2
    idx2 = i * 2 + 1
    if digit % 2 == 0:
        val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    else:
        val = (shell_m[idx1] + shell_m[idx2]) // 10 % 256
    pairs.append(val)

print(f"Key: {bytes(pairs).hex()}")
print(f"First: {hex(pairs[0])}, 0x77 at: {[j for j,p in enumerate(pairs) if p==0x77]}")
