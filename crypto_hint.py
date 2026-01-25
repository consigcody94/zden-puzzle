"""
Using the "crypto" hint more directly.
From the analysis, specific shell/div combinations give 'crypto' ASCII values.
"""
import hashlib
import ecdsa
import base58
import itertools

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
print("CRYPTO HINT EXPLORATION")
print("="*70)

# ============================================================================
# 1. Find all (idx, div) that produce each 'crypto' letter
# ============================================================================
print("\n[1] Finding all 'crypto' producers...")

crypto = "crypto"
crypto_producers = {c: [] for c in crypto}

for c in crypto:
    target_val = ord(c)
    for div in range(1, 100):
        for idx in range(64):
            if shell[idx] // div % 256 == target_val:
                crypto_producers[c].append((idx, div))

for c in crypto:
    print(f"  '{c}' ({ord(c)}): {len(crypto_producers[c])} producers")
    for idx, div in crypto_producers[c][:3]:
        print(f"    shell[{idx}] // {div} = {shell[idx] // div}")

# ============================================================================
# 2. Build keys where first bytes spell 'crypto'
# ============================================================================
print("\n[2] Keys starting with 'crypto'...")

# Get the producer options for each letter
c_opts = crypto_producers['c']
r_opts = crypto_producers['r']
y_opts = crypto_producers['y']
p_opts = crypto_producers['p']
t_opts = crypto_producers['t']
o_opts = crypto_producers['o']

best = 0
for c_idx, c_div in c_opts[:5]:
    for r_idx, r_div in r_opts[:5]:
        for y_idx, y_div in y_opts[:5]:
            for p_idx, p_div in p_opts[:5]:
                for t_idx, t_div in t_opts[:5]:
                    for o_idx, o_div in o_opts[:5]:
                        # Build key with crypto at start
                        key = [ord(c) for c in "crypto"]  # First 6 bytes

                        # Fill rest with standard formula
                        for i in range(6, 32):
                            key.append((shell[i*2] + shell[i*2+1]) // 7 % 256)

                        addr = privkey_to_address(bytes(key), True)
                        match = count_match(addr)
                        if match > best:
                            best = match
                            print(f"  'crypto' start: {match} chars - {addr[:15]}...")

                        if check_key(key, f"crypto_start"):
                            exit()

print(f"Best with 'crypto' start: {best}")

# ============================================================================
# 3. Variable divisor per position based on digit sequence
# ============================================================================
print("\n[3] Variable divisor per position...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

# Each digit could indicate divisor offset
for base_div in [5, 6, 7]:
    key = []
    for i in range(32):
        digit = all_digits[i % 16]
        div = base_div + digit
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    print(f"  base_div {base_div} + digit: {match} chars - {addr[:15] if addr else 'None'}...")
    if check_key(key, f"var_div_{base_div}"):
        exit()

# ============================================================================
# 4. Use different rectangles for different positions
# ============================================================================
print("\n[4] Position-dependent rect selection...")

for div in [7, 10]:
    for offset in range(32):
        key = []
        for i in range(32):
            # Use (i + offset) % 64 instead of i*2
            idx = (i + offset) % 64
            key.append(shell[idx] // div % 256)

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 4:
            print(f"  offset {offset} div{div}: {match} chars")

        if check_key(key, f"offset_{offset}_div{div}"):
            exit()

# ============================================================================
# 5. The "GeCRiTz" from target - upper/lower case pattern?
# ============================================================================
print("\n[5] GeCRiTz pattern...")

# G=71, e=101, C=67, R=82, i=105, T=84, z=122
gecritz_vals = [71, 101, 67, 82, 105, 84, 122]

# Find which shell/div produce these
for i, val in enumerate(gecritz_vals):
    found = []
    for div in range(1, 50):
        for idx in range(64):
            if shell[idx] // div % 256 == val:
                found.append((idx, div))
                break
        if found:
            break
    if found:
        print(f"  'GeCRiTz'[{i}]={chr(val)}({val}): shell[{found[0][0]}] // {found[0][1]}")

# ============================================================================
# 6. What if the key encodes to produce "1crypto..." address?
# ============================================================================
print("\n[6] Vanity address patterns...")

# The address starts with "1crypto" which is unusual - it's a vanity address
# What if the puzzle is about finding THE key that produces this specific vanity?

# Try brute force with shell-based variations
import random
random.seed(77)

best = 0
for trial in range(500000):
    # Generate key based on shell values with random variations
    key = []
    for i in range(32):
        variation = random.randint(0, 3)
        div = random.choice([7, 10, 17])

        if variation == 0:
            val = shell[i] // div % 256
        elif variation == 1:
            val = (shell[i*2 % 64] + shell[(i*2+1) % 64]) // div % 256
        elif variation == 2:
            val = shell[(i + 32) % 64] // div % 256
        else:
            val = (outer[i % 64] - inner[i % 64]) // div % 256

        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match > best:
        best = match
        print(f"  Trial {trial}: {match} chars - {addr[:15]}...")

    if check_key(key, f"vanity_{trial}"):
        exit()

    if trial % 100000 == 0 and trial > 0:
        print(f"  ...{trial} trials, best: {best}")

print(f"\nBest vanity search: {best}")

# ============================================================================
# 7. The numbers 7, 10, 17, 39, 40, 57, 64 - what if they're all involved?
# ============================================================================
print("\n[7] All magic numbers combined...")

magic = [7, 10, 17, 39, 40, 57, 64]

# Try different combinations
for m1 in magic:
    for m2 in magic:
        if m1 == m2:
            continue
        key = []
        for i in range(32):
            idx = (m1 + i * m2) % 64
            val = shell[idx] // 7 % 256
            key.append(val)

        if check_key(key, f"magic_{m1}_{m2}"):
            exit()

print("\n" + "="*70)
print("Crypto hint exploration complete")
print("="*70)
