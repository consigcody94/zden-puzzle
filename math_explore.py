"""
Exploring mathematical relationships in the puzzle.
"""
import hashlib
import ecdsa
import base58
import random

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

def count_match(addr):
    if not addr:
        return 0
    return sum(1 for a, b in zip(addr, TARGET) if a == b)

print("="*70)
print("MATHEMATICAL EXPLORATION")
print("="*70)

# ============================================================================
# 1. Look for mathematical relationships in shell values
# ============================================================================
print("\n[1] Shell value relationships...")

# Check for patterns like shell[i] = a*i + b
# or shell[i+1] - shell[i] = constant
differences = [shell[i+1] - shell[i] for i in range(63)]
print(f"Max difference: {max(differences)}, Min: {min(differences)}")

# Look for repeating patterns
for period in [2, 4, 8, 16, 32]:
    same_count = sum(1 for i in range(64 - period) if shell[i] == shell[i + period])
    if same_count > 0:
        print(f"  Period {period}: {same_count} repetitions")

# ============================================================================
# 2. Modular arithmetic with primes
# ============================================================================
print("\n[2] Prime modular arithmetic...")

primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]
for p in primes:
    key = [shell[i] % p for i in range(32)]
    # Scale to byte range
    key = [k * (255 // p) for k in key]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  mod {p}: {match} chars")
    if check_key(key, f"mod_prime_{p}"):
        exit()

# ============================================================================
# 3. Polynomial evaluation
# ============================================================================
print("\n[3] Polynomial interpretations...")

# What if each rectangle encodes coefficients of a polynomial?
# Evaluate at specific points
for x in [2, 7, 10, 17]:
    key = []
    for i in range(32):
        a, b, c = outer[i], inner[i], shell[i]
        val = (a * x * x + b * x + c) // 1000 % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  Poly eval at x={x}: {match} chars")
    if check_key(key, f"poly_{x}"):
        exit()

# ============================================================================
# 4. Geometric interpretations
# ============================================================================
print("\n[4] Geometric interpretations...")

# outer = width * height, inner = (w-2t) * (h-2t) for thickness t
# shell = outer - inner
# What if we can derive t (thickness)?

# Actually: shell = 2*t*(w + h - 2*t) for a rectangular frame
# This is complex, but shell values might encode something

# Area ratios
for scale in [1, 10, 100]:
    key = []
    for i in range(32):
        if outer[i] > 0:
            ratio = int((shell[i] * scale * 256) / outer[i]) % 256
        else:
            ratio = 0
        key.append(ratio)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  Area ratio scale {scale}: {match} chars")
    if check_key(key, f"area_ratio_{scale}"):
        exit()

# ============================================================================
# 5. Binary decomposition
# ============================================================================
print("\n[5] Binary decomposition...")

# Take specific bits from shell values
for bit in range(12):
    key = []
    for i in range(32):
        val = (shell[i] >> bit) & 0xFF
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  Bits [{bit}:{bit+8}]: {match} chars")
    if check_key(key, f"bits_{bit}"):
        exit()

# ============================================================================
# 6. Continued fraction expansion
# ============================================================================
print("\n[6] Fraction-based...")

# What if outer/inner encodes something?
key = []
for i in range(32):
    if inner[i] > 0:
        quot = outer[i] // inner[i]
        rem = outer[i] % inner[i]
        val = (quot * 16 + rem % 16) % 256
    else:
        val = 0
    key.append(val)

addr = privkey_to_address(bytes(key), True)
print(f"  Quotient + rem: {count_match(addr)} chars")
if check_key(key, "quot_rem"):
    exit()

# ============================================================================
# 7. Sum of subset shells
# ============================================================================
print("\n[7] Subset sums...")

# Maybe byte i is sum of specific subset of shells
for pattern in ['even', 'odd', 'low', 'high']:
    key = []
    for i in range(32):
        if pattern == 'even':
            indices = [j for j in range(64) if j % 2 == 0][:i+1]
        elif pattern == 'odd':
            indices = [j for j in range(64) if j % 2 == 1][:i+1]
        elif pattern == 'low':
            indices = list(range(i+1))
        else:
            indices = list(range(32, 32+i+1))

        val = sum(shell[j] for j in indices) // 7 % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  {pattern}: {match} chars")
    if check_key(key, f"subset_{pattern}"):
        exit()

# ============================================================================
# 8. Matrix operations
# ============================================================================
print("\n[8] Matrix operations...")

# Treat 64 rects as 8x8 matrix
def get_matrix_val(row, col):
    return shell[row * 8 + col]

# Row sums
key = []
for i in range(8):
    for j in range(4):
        val = sum(get_matrix_val(i, k) for k in range(8)) // 10 % 256
        key.append(val)

if len(key) == 32:
    addr = privkey_to_address(bytes(key), True)
    print(f"  Row sums: {count_match(addr)} chars")
    if check_key(key, "row_sums"):
        exit()

# Column sums
key = []
for j in range(8):
    for i in range(4):
        val = sum(get_matrix_val(k, j) for k in range(8)) // 10 % 256
        key.append(val)

if len(key) == 32:
    addr = privkey_to_address(bytes(key), True)
    print(f"  Col sums: {count_match(addr)} chars")
    if check_key(key, "col_sums"):
        exit()

# ============================================================================
# 9. Extensive random with shell patterns
# ============================================================================
print("\n[9] Extensive random search...")

random.seed(42)
best = 0

for trial in range(500000):
    # Various generation methods
    method = trial % 10

    if method == 0:
        # Random indices
        indices = random.sample(range(64), 32)
        div = random.choice([7, 10, 17])
        key = [shell[idx] // div % 256 for idx in indices]

    elif method == 1:
        # Step pattern with random params
        start = random.randint(0, 63)
        step = random.randint(2, 63)
        div = random.choice([7, 10])
        indices = [(start + i * step) % 64 for i in range(32)]
        key = [shell[idx] // div % 256 for idx in indices]

    elif method == 2:
        # Pairs with random operation
        div = random.choice([7, 10, 17])
        op = random.choice(['add', 'sub', 'xor'])
        key = []
        for i in range(32):
            a, b = shell[i*2], shell[i*2+1]
            if op == 'add':
                val = (a + b) // div % 256
            elif op == 'sub':
                val = abs(a - b) // div % 256
            else:
                val = (a ^ b) // div % 256
            key.append(val)

    elif method == 3:
        # Mixed components
        div = random.choice([7, 10, 20])
        key = []
        for i in range(32):
            comp = random.choice([outer, inner, shell])
            key.append(comp[i] // div % 256)

    elif method == 4:
        # Modify known good base
        indices = [(57 + i * 3) % 64 for i in range(32)]
        key = [shell[idx] // 7 % 256 for idx in indices]
        key[23] = 176
        for _ in range(random.randint(1, 4)):
            key[random.randint(0, 31)] = random.randint(0, 255)

    elif method == 5:
        # All shell with random divisor per byte
        key = []
        for i in range(32):
            div = random.randint(1, 20)
            key.append(shell[i] // div % 256)

    elif method == 6:
        # Formula: (a*shell[i] + b*shell[j]) / c
        a = random.randint(1, 10)
        b = random.randint(1, 10)
        c = random.randint(1, 20)
        key = []
        for i in range(32):
            j = (i + random.randint(1, 32)) % 64
            val = (a * shell[i] + b * shell[j]) // c % 256
            key.append(val)

    elif method == 7:
        # FIX pattern variants
        mult = random.randint(1, 30)
        shell_m = shell.copy()
        pos = random.randint(0, 63)
        shell_m[pos] *= mult
        div = random.choice([7, 10])
        key = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

    elif method == 8:
        # Completely random
        key = [random.randint(0, 255) for _ in range(32)]

    else:
        # Hash-based
        seed = random.randint(0, 10000)
        shell_bytes = b''.join(s.to_bytes(2, 'big') for s in shell)
        h = hashlib.sha256(str(seed).encode() + shell_bytes).digest()
        key = list(h)

    for comp in [True, False]:
        addr = privkey_to_address(bytes(key), comp)
        match = count_match(addr)

        if match > best:
            best = match
            c = "C" if comp else "U"
            print(f"  Trial {trial} m{method} [{c}]: {match} - {addr[:15]}...")

        if check_key(key, f"random_{trial}_{method}"):
            exit()

    if trial % 100000 == 0 and trial > 0:
        print(f"  ...{trial} trials, best: {best}")

print(f"\nBest random: {best}")

print("\n" + "="*70)
print("Mathematical exploration complete")
print("="*70)
