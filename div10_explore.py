"""
KEY FINDINGS from digit sum exploration:
1. Div 10 gives 0x77 at position 16 (boundary between halves!)
2. First byte IS 0x28 (40 in hex) with div 7 - matches digit sum total!
3. XOR with 40 gives 0x77 at position 18
4. Formula (-I*30+64)/10 gives 0x77 at position 3

Let's explore div 10 and the 0x28 first byte more deeply!
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
print("DIV 10 AND FIRST BYTE 0x28 EXPLORATION")
print("="*70)

# ============================================================================
# Output the div10 key
# ============================================================================
print("[1] Div 10 baseline...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 10 % 256 for i in range(32)]
        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]

        print(f"  m{mult39}_{mult52}: {[hex(p) for p in pairs[:8]]}...")
        print(f"    0x77 at: {has_77}, first byte: {hex(pairs[0])}")
        check_key(pairs, f"div10_m{mult39}_{mult52}")

# ============================================================================
# Combine div 10 with div 7 (one for each half)
# ============================================================================
print("\n[2] Split: div7 for first 16, div10 for last 16...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = []
        for i in range(32):
            div = 7 if i < 16 else 10
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        print(f"  m{mult39}_{mult52}: 0x77 at {has_77}, first: {hex(pairs[0])}")
        if check_key(pairs, f"div7_10_split_m{mult39}_{mult52}"):
            exit()

# ============================================================================
# Try div 30 for first half, div 10 for second half
# ============================================================================
print("\n[3] Split: div30 for first 16, div10 for last 16...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = []
        for i in range(32):
            div = 30 if i < 16 else 10
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"div30_10_split_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# X = 10 in the formula -I*X+LXIV/X
# ============================================================================
print("\n[4] Formula with X=10: (Shell - Inner*10 + 64) / 10...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52
        inner_m[39] *= mult39
        inner_m[52] *= mult52

        pairs = []
        for i in range(32):
            S = shell_m[i*2] + shell_m[i*2+1]
            I = inner_m[i*2] + inner_m[i*2+1]
            result = (S - I * 10 + 64) // 10 % 256
            pairs.append(result)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  F(X=10) m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"formula_X10_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# First byte must be 0x28, look for patterns that maintain this
# ============================================================================
print("\n[5] Patterns where first byte = 0x28...")

# shell[0] + shell[1] = 2484 + 1384 = 3868
# 3868 / 7 = 552.57... % 256 = 40 = 0x28 (works!)
# What divisor gives 0x28 for the first byte?

sum_01 = shell[0] + shell[1]
print(f"  shell[0] + shell[1] = {sum_01}")
print(f"  {sum_01} / 7 = {sum_01 // 7} % 256 = {sum_01 // 7 % 256} (0x{sum_01 // 7 % 256:02x})")
print(f"  {sum_01} / 10 = {sum_01 // 10} % 256 = {sum_01 // 10 % 256} (0x{sum_01 // 10 % 256:02x})")

# Find all divisors that give 0x28 for the first byte
print("\n  Divisors giving first byte = 0x28:")
for d in range(1, 200):
    if (sum_01 // d) % 256 == 0x28:
        print(f"    div {d}: {sum_01} // {d} = {sum_01 // d} % 256 = {(sum_01 // d) % 256}")

# ============================================================================
# Combined: first byte = 0x28 AND contains 0x77
# ============================================================================
print("\n[6] Keys with first byte 0x28 AND containing 0x77...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 63, 96]:  # Divisors that might give 0x28
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            if pairs[0] == 0x28 and 0x77 in pairs:
                print(f"  div{div} m{mult39}_{mult52}: first=0x28, 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"first28_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Maybe combine the digit sums: use 30 as multiplier at position 0, etc.
# ============================================================================
print("\n[7] Position-based digit application...")

digits_before = [0, 9, 1, 1, 1, 8, 1, 9]
digits_after = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = digits_before + digits_after  # 16 values

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for base_div in [7, 10, 64]:
            pairs = []
            for i in range(32):
                digit = all_digits[i % 16]
                # Use digit as modifier
                val = (shell_m[i*2] + shell_m[i*2+1] + digit * 10) // base_div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  DigitMod div{base_div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"digitmod_div{base_div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# The 16th position (boundary) being 0x77 with div10 is significant
# Maybe the key is split at position 16
# ============================================================================
print("\n[8] Split key at position 16...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        # First 16 with div7, last 16 with div10
        first16 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(16)]
        last16 = [(shell_m[(16+i)*2] + shell_m[(16+i)*2+1]) // 10 % 256 for i in range(16)]

        pairs = first16 + last16
        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        print(f"  Split7_10 m{mult39}_{mult52}: 0x77 at {has_77}, first: {hex(pairs[0])}")
        if check_key(pairs, f"split7_10_m{mult39}_{mult52}"):
            exit()

# ============================================================================
# What if we XOR the result with the digit at that position?
# ============================================================================
print("\n[9] XOR with digit sequence...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR with cycling digit pattern
            pairs = []
            for i in range(32):
                digit = all_digits[i % 16]
                pairs.append(base[i] ^ digit)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  XOR_digit div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"xor_digit_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# The position 16 and 19 both can have 0x77
# What if we need both?
# ============================================================================
print("\n[10] Keys with 0x77 at both positions 16 and 19...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        # Base key with div7 (has 0x77 at 19 with m17)
        base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

        # Force position 16 to 0x77
        pairs = base.copy()
        pairs[16] = 0x77

        if pairs[19] == 0x77:
            print(f"  m{mult39}_{mult52}: 0x77 at both 16 and 19!")
            if check_key(pairs, f"both16_19_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# Try the full digit sum interpretation:
# Byte i uses divisor based on digit at position i
# ============================================================================
print("\n[11] Divisor based on digit value...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = []
        for i in range(32):
            digit = all_digits[i % 16]
            if digit == 0:
                div = 10  # Use 10 for digit 0
            else:
                div = digit * 10  # Use digit * 10 as divisor

            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  DigitDiv m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"digitdiv_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# Output promising candidates
# ============================================================================
print("\n" + "="*70)
print("PROMISING CANDIDATES")
print("="*70)

# Candidate 1: div7, mult17 at rect39 (has 0x77 at 19, first byte 0x28)
shell_m = shell.copy()
shell_m[39] *= 17
pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
print("\nCandidate 1 (div7, m17): ")
print(f"  Hex: {''.join(f'{p:02x}' for p in pairs)}")
print(f"  First byte: {hex(pairs[0])}, 0x77 at: {[i for i,p in enumerate(pairs) if p==0x77]}")

# Candidate 2: div10 (has 0x77 at 16)
pairs = [(shell[i*2] + shell[i*2+1]) // 10 % 256 for i in range(32)]
print("\nCandidate 2 (div10): ")
print(f"  Hex: {''.join(f'{p:02x}' for p in pairs)}")
print(f"  First byte: {hex(pairs[0])}, 0x77 at: {[i for i,p in enumerate(pairs) if p==0x77]}")

# Candidate 3: Split div7/div10
shell_m = shell.copy()
shell_m[39] *= 17
first16 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(16)]
last16 = [(shell_m[(16+i)*2] + shell_m[(16+i)*2+1]) // 10 % 256 for i in range(16)]
pairs = first16 + last16
print("\nCandidate 3 (split div7/div10, m17): ")
print(f"  Hex: {''.join(f'{p:02x}' for p in pairs)}")
print(f"  First byte: {hex(pairs[0])}, 0x77 at: {[i for i,p in enumerate(pairs) if p==0x77]}")

print("\nDiv10 exploration complete.")
