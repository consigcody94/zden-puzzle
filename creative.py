"""
Creative/alternative approaches to the puzzle.
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

def count_match(addr):
    if not addr:
        return 0
    return sum(1 for a, b in zip(addr, TARGET) if a == b)

print("="*70)
print("CREATIVE APPROACHES")
print("="*70)

# ============================================================================
# 1. What if the rectangles encode coordinates?
# ============================================================================
print("\n[1] Coordinates interpretation...")

# Maybe (outer, inner) are (x, y) coordinates and we extract something
for div in [100, 1000, 10000]:
    key = []
    for i in range(32):
        x = outer[i] // div
        y = inner[i] // div
        val = (x + y) % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Coords div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"coords_{div}"):
        exit()

# ============================================================================
# 2. Prime factorization of shell values
# ============================================================================
print("\n[2] Prime-related...")

def smallest_prime_factor(n):
    if n < 2:
        return 1
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return i
    return n

key = [smallest_prime_factor(s) % 256 for s in shell[:32]]
addr = privkey_to_address(bytes(key), True)
print(f"  Smallest prime factor: {addr}, match: {count_match(addr)}")
if check_key(key, "prime_factor"):
    exit()

# ============================================================================
# 3. Fibonacci-like combinations
# ============================================================================
print("\n[3] Fibonacci combinations...")

for div in [7, 10]:
    key = []
    a, b = 0, 1
    for i in range(32):
        val = (shell[a % 64] + shell[b % 64]) // div % 256
        key.append(val)
        a, b = b, a + b

    addr = privkey_to_address(bytes(key), True)
    print(f"  Fib indices div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"fib_{div}"):
        exit()

# ============================================================================
# 4. Using the target address as a hint
# ============================================================================
print("\n[4] Target address hints...")

# "crypto" in target - maybe use ASCII values
# c=99, r=114, y=121, p=112, t=116, o=111
crypto_vals = [99, 114, 121, 112, 116, 111]

# Try to find which shell indices give these values
for div in range(1, 20):
    for i, target_val in enumerate(crypto_vals):
        for j in range(64):
            if shell[j] // div % 256 == target_val:
                print(f"  'crypto'[{i}]={target_val}: shell[{j}] div {div}")
                break

# ============================================================================
# 5. Maybe the hash160 of the address tells us something
# ============================================================================
print("\n[5] Hash160 analysis...")

decoded = base58.b58decode(TARGET)
h160 = decoded[1:21]
print(f"Target hash160: {h160.hex()}")
print(f"First 4 bytes: {list(h160[:4])}")

# What if the key directly produces this hash160?
# The first byte is 0x06 = 6

# ============================================================================
# 6. Decimal digit extraction
# ============================================================================
print("\n[6] Decimal digits...")

# Take specific decimal digits from shell values
for digit_pos in [0, 1, 2, 3]:
    key = []
    for s in shell[:32]:
        digits = str(s)
        if digit_pos < len(digits):
            key.append(int(digits[digit_pos]) * 25)  # Scale to 0-225
        else:
            key.append(0)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Digit position {digit_pos}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"digit_pos_{digit_pos}"):
        exit()

# ============================================================================
# 7. Checksum of values
# ============================================================================
print("\n[7] Checksum approaches...")

# Running checksum
key = []
checksum = 0
for i in range(32):
    checksum = (checksum + shell[i]) % 256
    key.append(checksum)

addr = privkey_to_address(bytes(key), True)
print(f"  Running sum: {addr}, match: {count_match(addr)}")
if check_key(key, "running_checksum"):
    exit()

# Running XOR
key = []
xor_val = 0
for i in range(32):
    xor_val ^= shell[i]
    key.append(xor_val % 256)

addr = privkey_to_address(bytes(key), True)
print(f"  Running XOR: {addr}, match: {count_match(addr)}")
if check_key(key, "running_xor"):
    exit()

# ============================================================================
# 8. Area ratios
# ============================================================================
print("\n[8] Area ratios...")

# shell / outer ratio scaled
key = []
for i in range(32):
    if outer[i] > 0:
        ratio = int(shell[i] * 256 / outer[i])
    else:
        ratio = 0
    key.append(ratio % 256)

addr = privkey_to_address(bytes(key), True)
print(f"  Shell/Outer ratio: {addr}, match: {count_match(addr)}")
if check_key(key, "shell_outer_ratio"):
    exit()

# ============================================================================
# 9. Bit interleaving
# ============================================================================
print("\n[9] Bit operations...")

# Take alternating bits from consecutive shell values
key = []
for i in range(32):
    s1 = shell[i*2] if i*2 < 64 else 0
    s2 = shell[i*2+1] if i*2+1 < 64 else 0
    # Interleave low bits
    val = 0
    for bit in range(4):
        val |= ((s1 >> bit) & 1) << (bit * 2)
        val |= ((s2 >> bit) & 1) << (bit * 2 + 1)
    key.append(val % 256)

addr = privkey_to_address(bytes(key), True)
print(f"  Bit interleave: {addr}, match: {count_match(addr)}")
if check_key(key, "bit_interleave"):
    exit()

# ============================================================================
# 10. Rectangle "color" or position-based encoding
# ============================================================================
print("\n[10] Position-based encoding...")

# What if rectangles are arranged in an 8x8 grid?
for row_major in [True, False]:
    for div in [7, 10]:
        key = []
        for i in range(32):
            if row_major:
                row = i // 4
                col = i % 4
                idx = row * 8 + col
            else:
                row = i % 4
                col = i // 4
                idx = row * 8 + col

            if idx < 64:
                key.append(shell[idx] // div % 256)
            else:
                key.append(0)

        order = "row" if row_major else "col"
        addr = privkey_to_address(bytes(key), True)
        print(f"  Grid {order} div{div}: {addr}, match: {count_match(addr)}")
        if check_key(key, f"grid_{order}_{div}"):
            exit()

# ============================================================================
# 11. Diagonal reading
# ============================================================================
print("\n[11] Diagonal patterns...")

# Read diagonally from 8x8 grid
indices = []
for d in range(16):  # 16 diagonals
    for i in range(8):
        j = d - i
        if 0 <= j < 8:
            indices.append(i * 8 + j)
        if len(indices) >= 32:
            break
    if len(indices) >= 32:
        break

for div in [7, 10]:
    key = [shell[idx] // div % 256 for idx in indices[:32]]
    addr = privkey_to_address(bytes(key), True)
    print(f"  Diagonal div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"diagonal_{div}"):
        exit()

# ============================================================================
# 12. Spiral reading
# ============================================================================
print("\n[12] Spiral pattern...")

def spiral_order(n):
    indices = []
    left, right, top, bottom = 0, n-1, 0, n-1
    while left <= right and top <= bottom:
        for i in range(left, right+1):
            indices.append(top * n + i)
        top += 1
        for i in range(top, bottom+1):
            indices.append(i * n + right)
        right -= 1
        if top <= bottom:
            for i in range(right, left-1, -1):
                indices.append(bottom * n + i)
            bottom -= 1
        if left <= right:
            for i in range(bottom, top-1, -1):
                indices.append(i * n + left)
            left += 1
    return indices

spiral_idx = spiral_order(8)[:32]
for div in [7, 10]:
    key = [shell[idx] // div % 256 for idx in spiral_idx]
    addr = privkey_to_address(bytes(key), True)
    print(f"  Spiral div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"spiral_{div}"):
        exit()

# ============================================================================
# 13. Sum of triplet components
# ============================================================================
print("\n[13] Triplet sums...")

for div in [10, 20, 50, 100]:
    key = [(outer[i] + inner[i] + shell[i]) // div % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    print(f"  O+I+S div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"triplet_sum_{div}"):
        exit()

print("\n" + "="*70)
print("Creative approaches complete")
print("="*70)
