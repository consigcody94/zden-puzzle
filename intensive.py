"""
Intensive search around best candidates.
Previous best: 7 chars from random walk-53 modification.
"""
import hashlib
import ecdsa
import base58
import random
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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

print("="*70)
print("INTENSIVE SEARCH")
print("="*70)

# Build the walk-53 base key
base_key = []
pos = 53
for i in range(32):
    base_key.append(shell[pos] // 7 % 256)
    digit = all_digits[i % 16]
    pos = (pos + digit + 1) % 64

print(f"Base key: {bytes(base_key).hex()}")

# ============================================================================
# 1. Exhaustive 2-byte search
# ============================================================================
print("\n[1] Exhaustive 2-byte search...")

best = 7
best_key = None
for p1 in range(32):
    for p2 in range(p1+1, 32):
        for v1 in range(256):
            for v2 in range(256):
                key = base_key.copy()
                key[p1] = v1
                key[p2] = v2

                for comp in [True, False]:
                    addr = privkey_to_address(bytes(key), comp)
                    match = count_match(addr)
                    if match > best:
                        best = match
                        best_key = key.copy()
                        c = "C" if comp else "U"
                        print(f"  p{p1}={v1}, p{p2}={v2} [{c}]: {match} chars - {addr[:20]}...")

                    if check_key(key, f"2byte_{p1}_{v1}_{p2}_{v2}"):
                        exit()

    print(f"  Completed p1={p1}")

print(f"\nBest 2-byte: {best}")

# ============================================================================
# 2. If we found a better key, search around it
# ============================================================================
if best_key and best > 7:
    print("\n[2] Searching around best key...")

    for p in range(32):
        for v in range(256):
            key = best_key.copy()
            key[p] = v

            for comp in [True, False]:
                if check_key(key, f"near_best_{p}_{v}"):
                    exit()

# ============================================================================
# 3. Different base keys - try all starting positions
# ============================================================================
print("\n[3] Different starting positions with 2-byte mods...")

for start in range(64):
    # Build key from this start
    key_base = []
    pos = start
    for i in range(32):
        key_base.append(shell[pos] // 7 % 256)
        digit = all_digits[i % 16]
        pos = (pos + digit + 1) % 64

    # Check base
    addr = privkey_to_address(bytes(key_base), True)
    base_match = count_match(addr)

    if base_match >= 4:
        # Try single-byte modifications
        for p in range(32):
            for v in range(256):
                key = key_base.copy()
                key[p] = v

                for comp in [True, False]:
                    addr = privkey_to_address(bytes(key), comp)
                    match = count_match(addr)
                    if match > best:
                        best = match
                        print(f"  start{start} p{p}={v}: {match} chars - {addr[:20]}...")

                    if check_key(key, f"start{start}_{p}_{v}"):
                        exit()

print(f"\nBest with different starts: {best}")

# ============================================================================
# 4. Try step patterns with modifications
# ============================================================================
print("\n[4] Step patterns with mods...")

for step in [2, 3, 5, 7, 17, 26]:
    for start in [0, 39, 57]:
        indices = [(start + i * step) % 64 for i in range(32)]
        key_base = [shell[idx] // 7 % 256 for idx in indices]

        addr = privkey_to_address(bytes(key_base), True)
        base_match = count_match(addr)

        if base_match >= 3:
            # Try single-byte modifications
            for p in range(32):
                for v in range(256):
                    key = key_base.copy()
                    key[p] = v

                    if check_key(key, f"step{step}_start{start}_{p}_{v}"):
                        exit()

# ============================================================================
# 5. Hybrid: walk + step
# ============================================================================
print("\n[5] Hybrid walk + step...")

for step in [2, 3, 5, 17]:
    for walk_start in [0, 53]:
        # First 16 from walk
        key = []
        pos = walk_start
        for i in range(16):
            key.append(shell[pos] // 7 % 256)
            digit = all_digits[i % 16]
            pos = (pos + digit + 1) % 64

        # Last 16 from step pattern
        for i in range(16):
            idx = (39 + i * step) % 64
            key.append(shell[idx] // 7 % 256)

        for comp in [True, False]:
            addr = privkey_to_address(bytes(key), comp)
            match = count_match(addr)
            if match >= 5:
                print(f"  walk{walk_start}+step{step}: {match} chars")

            if check_key(key, f"hybrid_walk{walk_start}_step{step}"):
                exit()

# ============================================================================
# 6. Massive random search
# ============================================================================
print("\n[6] Massive random search (1M trials)...")

random.seed(12345)
best_random = best

for trial in range(1000000):
    # Generate key based on various patterns
    pattern = trial % 5

    if pattern == 0:
        # Modify walk-53 base
        key = base_key.copy()
        num_mods = random.randint(1, 4)
        for _ in range(num_mods):
            key[random.randint(0, 31)] = random.randint(0, 255)

    elif pattern == 1:
        # Random step pattern
        start = random.randint(0, 63)
        step = random.randint(2, 63)
        div = random.choice([7, 10])
        indices = [(start + i * step) % 64 for i in range(32)]
        key = [shell[idx] // div % 256 for idx in indices]

    elif pattern == 2:
        # Random walk
        start = random.randint(0, 63)
        div = random.choice([7, 10])
        key = []
        pos = start
        for i in range(32):
            key.append(shell[pos] // div % 256)
            pos = (pos + random.randint(1, 10)) % 64

    elif pattern == 3:
        # Random pairs
        indices = random.sample(range(64), 32)
        div = random.choice([7, 10])
        key = [shell[idx] // div % 256 for idx in indices]

    else:
        # Completely random
        key = [random.randint(0, 255) for _ in range(32)]

    for comp in [True, False]:
        addr = privkey_to_address(bytes(key), comp)
        match = count_match(addr)
        if match > best_random:
            best_random = match
            c = "C" if comp else "U"
            print(f"  Trial {trial} [{c}]: {match} chars - {addr[:20]}...")

        if check_key(key, f"random_{trial}"):
            exit()

    if trial % 100000 == 0 and trial > 0:
        print(f"  ...{trial} trials, best: {best_random}")

print(f"\nBest random: {best_random}")

print("\n" + "="*70)
print("Intensive search complete")
print("="*70)
