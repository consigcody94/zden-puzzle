"""
Radical new approaches:

1. The 8-digit sequences might BE part of the key directly
2. The puzzle might use modular arithmetic differently
3. There might be a hash involved
4. The "FIX" might mean error correction

Let's also check if there's a pattern in how the target address
was generated.
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

print("="*70)
print("RADICAL NEW APPROACHES")
print("="*70)

# ============================================================================
# 1. What if the digit sequences ARE the key (in some encoding)?
# ============================================================================
print("\n[1] Digit sequences as direct key encoding...")

# 09111819 = 0x008B0CDB
# 11122111 = 0x00A9B73F
seq1_int = 9111819
seq2_int = 11122111

print(f"09111819 = {seq1_int} = {hex(seq1_int)}")
print(f"11122111 = {seq2_int} = {hex(seq2_int)}")

# Try combining them in different ways
for method in ['concat', 'xor', 'add', 'mult']:
    if method == 'concat':
        combined = (seq1_int << 32) | seq2_int
    elif method == 'xor':
        combined = seq1_int ^ seq2_int
    elif method == 'add':
        combined = seq1_int + seq2_int
    elif method == 'mult':
        combined = seq1_int * seq2_int

    # Convert to 32 bytes with padding
    key_bytes = combined.to_bytes(32, 'big')
    if check_key(list(key_bytes), f"seq_{method}"):
        exit()

    # Also try little endian
    try:
        key_bytes = combined.to_bytes(32, 'little')
        if check_key(list(key_bytes), f"seq_{method}_le"):
            exit()
    except:
        pass

# ============================================================================
# 2. What if we need to use the FULL number 0911181911122111?
# ============================================================================
print("\n[2] Full sequence as number...")

full_seq = 911181911122111

try:
    # As bytes
    key_bytes = full_seq.to_bytes(32, 'big')
    if check_key(list(key_bytes), "full_seq_big"):
        exit()
except:
    pass

# Hash it
full_hash = hashlib.sha256(str(full_seq).encode()).digest()
if check_key(list(full_hash), "full_seq_hash"):
    exit()

# ============================================================================
# 3. What if the target address hash160 gives us hints?
# ============================================================================
print("\n[3] Analyzing target address...")

decoded = base58.b58decode(TARGET)
hash160 = decoded[1:21]
print(f"Target hash160: {hash160.hex()}")

# What if we need to find a key that XORs with something to give hash160?
# (This doesn't make cryptographic sense, but let's try)

# ============================================================================
# 4. What if the base key needs a hash transformation?
# ============================================================================
print("\n[4] Hash transformations of base key...")

shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    base.append(val)

# Try different hash seeds
for seed in [b'FIX', b'crypto', bytes([17]), bytes([39])]:
    h = hashlib.sha256(bytes(base) + seed).digest()
    if check_key(list(h), f"hash_seed_{seed[:4]}"):
        exit()

    h = hashlib.sha256(seed + bytes(base)).digest()
    if check_key(list(h), f"hash_seed_pre_{seed[:4]}"):
        exit()

# ============================================================================
# 5. What if we need to iterate until we find the right key?
# ============================================================================
print("\n[5] Iterative modification...")

# Add a counter to the key and try many values
for counter in range(10000):
    pairs = base.copy()
    # Modify last 4 bytes with counter
    counter_bytes = counter.to_bytes(4, 'big')
    for i in range(4):
        pairs[28 + i] = counter_bytes[i]

    if check_key(pairs, f"counter_{counter}"):
        exit()

print("  Counter search: no solution in first 10000")

# ============================================================================
# 6. What if each rectangle contributes to a specific byte position?
#    Based on some property
# ============================================================================
print("\n[6] Rectangle-to-position mapping...")

# Sort rectangles by shell value and use that order
sorted_indices = sorted(range(64), key=lambda i: shell[i])
print(f"Sorted by shell: first 10 = {sorted_indices[:10]}")

for div in [7, 10]:
    pairs = []
    for i in range(32):
        idx = sorted_indices[i * 2]
        idx2 = sorted_indices[i * 2 + 1]
        val = (shell[idx] + shell[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Sorted pairing div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"sorted_div{div}"):
            exit()

# ============================================================================
# 7. What if the "following" pattern is based on modular arithmetic?
# ============================================================================
print("\n[7] Modular following patterns...")

for mod in [7, 10, 17, 64]:
    for start in [0, 39, 57]:
        pairs = []
        idx = start
        for i in range(32):
            val = shell[idx] // 7 % 256
            pairs.append(val)
            idx = (idx * 3 + 1) % mod % 64  # Linear congruential

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  LCG mod{mod} start{start}: 0x77 at {has_77}")
            if check_key(pairs, f"lcg_mod{mod}_start{start}"):
                exit()

# ============================================================================
# 8. What if we combine multiple shell values per byte?
# ============================================================================
print("\n[8] Multiple shells per byte...")

for num_shells in [4, 8]:
    for div in [7, 10, 17]:
        pairs = []
        for i in range(32):
            total = sum(shell[(i * num_shells + j) % 64] for j in range(num_shells))
            val = total // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  {num_shells} shells div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"{num_shells}shells_div{div}"):
                exit()

# ============================================================================
# 9. What if the puzzle uses a specific secp256k1 operation?
# ============================================================================
print("\n[9] Try base key as scalar multiplication factor...")

# The base key might need to be used as a multiplier for a base point
# But that's the normal way... Let's try with different base values

# ============================================================================
# 10. Brute force with pattern constraints
# ============================================================================
print("\n[10] Constrained brute force...")

# We know: first byte likely 0x28, byte 19 likely 0x77
# Try all combinations of remaining bytes (too many, so sample)

import random
random.seed(42)

for trial in range(50000):
    pairs = base.copy()
    # Keep first byte and byte 19, randomize others
    for i in range(32):
        if i not in [0, 19]:
            pairs[i] = random.randint(0, 255)

    if check_key(pairs, f"random_{trial}"):
        exit()

print("  Random sampling: no solution in 50000 trials")

# ============================================================================
# 11. What if the answer is simpler? Try without multiplier
# ============================================================================
print("\n[11] Simple consecutive pairs, various divisors...")

for div in range(1, 20):
    pairs = []
    for i in range(32):
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        pairs.append(val)

    if check_key(pairs, f"simple_div{div}"):
        exit()

# ============================================================================
# 12. What about the three components (O, I, O-I=S)?
# ============================================================================
print("\n[12] Three-way combinations...")

for div in [7, 10]:
    # O + I + S
    pairs = []
    for i in range(32):
        val = (outer[i*2] + inner[i*2] + shell[i*2] +
               outer[i*2+1] + inner[i*2+1] + shell[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  O+I+S div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"ois_div{div}"):
            exit()

    # O * I / S
    pairs = []
    for i in range(32):
        s = shell[i*2] + shell[i*2+1]
        if s > 0:
            val = (outer[i*2] + outer[i*2+1]) * (inner[i*2] + inner[i*2+1]) // s // div % 256
        else:
            val = 0
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  O*I/S div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"oi_s_div{div}"):
            exit()

print("\n" + "="*70)
print("Radical approaches complete, no solution found")
print("="*70)

print("\nThe puzzle remains unsolved. Key observations:")
print("1. First byte 0x28 (40) matches digit sum total")
print("2. Byte 19 can be 0x77 (119) with the right formula")
print("3. The exact transformation is still missing")
