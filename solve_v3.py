"""
Radical approaches - completely different encodings.
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
print("SOLVE V3 - RADICAL APPROACHES")
print("="*70)

# ============================================================================
# 1. Single rectangle per byte (first 32, last 32, etc.)
# ============================================================================
print("\n[1] Single rect per byte...")

for start in [0, 16, 32]:
    for div in range(1, 20):
        pairs = [shell[(start + i) % 64] // div % 256 for i in range(32)]
        if check_key(pairs, f"single_start{start}_div{div}"):
            exit()

for div in range(1, 20):
    pairs = [shell[i * 2] // div % 256 for i in range(32)]  # Even indices only
    if check_key(pairs, f"even_div{div}"):
        exit()

    pairs = [shell[i * 2 + 1] // div % 256 for i in range(32)]  # Odd indices only
    if check_key(pairs, f"odd_div{div}"):
        exit()

print("  No solution")

# ============================================================================
# 2. Shell value mod 256 directly
# ============================================================================
print("\n[2] Shell mod 256...")

for start in [0, 32]:
    pairs = [shell[(start + i) % 64] % 256 for i in range(32)]
    if check_key(pairs, f"mod256_start{start}"):
        exit()

pairs = [(shell[i] + shell[i + 32]) % 256 for i in range(32)]
if check_key(pairs, "sum_halves_mod256"):
    exit()

print("  No solution")

# ============================================================================
# 3. High byte and low byte separately
# ============================================================================
print("\n[3] High/low byte extraction...")

for offset in [0, 32]:
    pairs = [(shell[(offset + i) % 64] >> 8) % 256 for i in range(32)]
    if check_key(pairs, f"high_byte_{offset}"):
        exit()

    pairs = [shell[(offset + i) % 64] & 0xFF for i in range(32)]
    if check_key(pairs, f"low_byte_{offset}"):
        exit()

print("  No solution")

# ============================================================================
# 4. Use outer directly
# ============================================================================
print("\n[4] Outer values directly...")

for div in range(10, 100, 5):
    pairs = [outer[i] // div % 256 for i in range(32)]
    if check_key(pairs, f"outer_single_div{div}"):
        exit()

print("  No solution")

# ============================================================================
# 5. Use inner directly
# ============================================================================
print("\n[5] Inner values directly...")

for div in range(10, 100, 5):
    pairs = [inner[i] // div % 256 for i in range(32)]
    if check_key(pairs, f"inner_single_div{div}"):
        exit()

print("  No solution")

# ============================================================================
# 6. XOR of outer and inner
# ============================================================================
print("\n[6] XOR outer/inner...")

for div in [1, 7, 10]:
    pairs = [(outer[i] ^ inner[i]) // div % 256 for i in range(32)]
    if check_key(pairs, f"xor_oi_div{div}"):
        exit()

print("  No solution")

# ============================================================================
# 7. Ratio-based
# ============================================================================
print("\n[7] Ratio based...")

# Shell/Outer ratio
for scale in [256, 512, 1024]:
    pairs = [(shell[i] * scale // outer[i]) % 256 if outer[i] > 0 else 0 for i in range(32)]
    if check_key(pairs, f"so_ratio_{scale}"):
        exit()

print("  No solution")

# ============================================================================
# 8. Hash of concatenated values
# ============================================================================
print("\n[8] Hash approaches...")

# Hash all shells
all_bytes = b''
for s in shell:
    all_bytes += s.to_bytes(2, 'big')
h = hashlib.sha256(all_bytes).digest()
if check_key(list(h), "sha256_all_shells"):
    exit()

# Hash with multiplier at 39
shell_m = shell.copy()
shell_m[39] *= 17
all_bytes = b''
for s in shell_m:
    all_bytes += s.to_bytes(2, 'big')
h = hashlib.sha256(all_bytes).digest()
if check_key(list(h), "sha256_shells_m17"):
    exit()

# Double SHA256
h = hashlib.sha256(hashlib.sha256(all_bytes).digest()).digest()
if check_key(list(h), "double_sha256"):
    exit()

print("  No solution")

# ============================================================================
# 9. Diagonal patterns in 8x8 grid
# ============================================================================
print("\n[9] Diagonal patterns...")

for div in [7, 10]:
    # Main diagonal and anti-diagonal
    diag = []
    for i in range(8):
        idx = i * 8 + i  # Main diagonal
        diag.append(shell[idx])
    for i in range(8):
        idx = i * 8 + (7 - i)  # Anti-diagonal
        diag.append(shell[idx])
    # Repeat to get 32
    diag = (diag * 2)[:32]
    pairs = [d // div % 256 for d in diag]
    if check_key(pairs, f"diagonal_div{div}"):
        exit()

print("  No solution")

# ============================================================================
# 10. Bit-level operations
# ============================================================================
print("\n[10] Bit operations...")

# Each rect contributes one bit per position
for threshold in [500, 1000, 1500, 2000]:
    bits = [1 if s > threshold else 0 for s in shell]
    # Pack into bytes
    pairs = []
    for i in range(32):
        byte_val = 0
        for j in range(8):
            idx = (i * 8 + j) % 64
            byte_val = (byte_val << 1) | bits[idx]
        pairs.append(byte_val)
    if check_key(pairs, f"bits_thresh{threshold}"):
        exit()

print("  No solution")

# ============================================================================
# 11. Prime factorization based
# ============================================================================
print("\n[11] Prime factor sums...")

def prime_factors_sum(n):
    if n <= 1:
        return 0
    total = 0
    d = 2
    while d * d <= n:
        while n % d == 0:
            total += d
            n //= d
        d += 1
    if n > 1:
        total += n
    return total

pairs = [prime_factors_sum(shell[i]) % 256 for i in range(32)]
if check_key(pairs, "prime_factor_sum"):
    exit()

print("  No solution")

# ============================================================================
# 12. Digit sum of shell values
# ============================================================================
print("\n[12] Digit sums of shells...")

def digit_sum(n):
    return sum(int(d) for d in str(n))

pairs = [digit_sum(shell[i]) for i in range(32)]
if check_key(pairs, "digit_sum_32"):
    exit()

pairs = [digit_sum(shell[i*2]) + digit_sum(shell[i*2+1]) for i in range(32)]
if check_key(pairs, "digit_sum_pairs"):
    exit()

print("  No solution")

# ============================================================================
# 13. ASCII encoding
# ============================================================================
print("\n[13] ASCII encoding...")

# Shell values as ASCII
pairs = [shell[i] % 128 for i in range(32)]  # Keep in ASCII range
if check_key(pairs, "ascii_shells"):
    exit()

print("  No solution")

# ============================================================================
# 14. Formula variations with the known good structure
# ============================================================================
print("\n[14] Formula variations...")

shell_m = shell.copy()
shell_m[39] *= 17
base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Multiply each byte by position
for mult in [1, 2, 3, 7, 17]:
    pairs = [(base[i] * (i + mult)) % 256 for i in range(32)]
    if check_key(pairs, f"pos_mult_{mult}"):
        exit()

# Add position
for add in [0, 1, 7, 17, 39]:
    pairs = [(base[i] + i + add) % 256 for i in range(32)]
    if check_key(pairs, f"pos_add_{add}"):
        exit()

print("  No solution")

# ============================================================================
# 15. Scramble based on mini-puzzle
# ============================================================================
print("\n[15] Mini-puzzle based scramble...")

seq = [0, 9, 1, 1, 1, 8, 1, 9, 1, 1, 1, 2, 2, 1, 1, 1]

# Use digits as permutation indices
perm = [(i + seq[i % 16]) % 32 for i in range(32)]
pairs = [base[perm[i]] for i in range(32)]
if check_key(pairs, "perm_add"):
    exit()

# Use digits as XOR values
pairs = [base[i] ^ seq[i % 16] for i in range(32)]
if check_key(pairs, "seq_xor"):
    exit()

# Scale by digits
pairs = [(base[i] * (seq[i % 16] + 1)) % 256 for i in range(32)]
if check_key(pairs, "seq_scale"):
    exit()

print("  No solution")

# ============================================================================
# 16. Exhaustive 4-byte modification on positions 1, 5, 10, 15
# ============================================================================
print("\n[16] 4-byte modification (sampled)...")

import random
random.seed(12345)

count = 0
for _ in range(100000):
    pairs = base.copy()
    # Random 4 positions
    positions = random.sample(range(1, 31), 4)  # Exclude 0 and keep 19
    for pos in positions:
        pairs[pos] = random.randint(0, 255)
    if check_key(pairs, f"random4_{count}"):
        exit()
    count += 1
    if count % 10000 == 0:
        print(f"  {count} tried...")

print(f"  {count} combinations: no solution")

print("\n" + "="*70)
print("V3 complete - no solution")
print("="*70)
