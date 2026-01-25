"""
Deep exploration of step 3 pattern.
step3 pos23=176 gave 10 char match.
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
print("STEP 3 DEEP EXPLORATION")
print("="*70)

# ============================================================================
# 1. Base step 3 pattern
# ============================================================================
print("\n[1] Step 3 base analysis...")

step = 3
indices = [(57 + i * step) % 64 for i in range(32)]
print(f"Indices: {indices}")
print(f"Position of 39: {indices.index(39) if 39 in indices else 'N/A'}")

base_key = [shell[idx] // 7 % 256 for idx in indices]
print(f"Base key: {bytes(base_key).hex()}")
addr = privkey_to_address(bytes(base_key), True)
print(f"Base address: {addr}, matches: {count_match(addr)}")

# Apply the best modification found
key_23_176 = base_key.copy()
key_23_176[23] = 176
addr = privkey_to_address(bytes(key_23_176), True)
print(f"With pos23=176: {addr}, matches: {count_match(addr)}")

# ============================================================================
# 2. Two-byte modifications on top of pos23=176
# ============================================================================
print("\n[2] Two-byte mods on pos23=176...")

best = 10
for pos2 in range(32):
    if pos2 == 23:
        continue
    for val2 in range(256):
        key = key_23_176.copy()
        key[pos2] = val2

        for comp in [True, False]:
            addr = privkey_to_address(bytes(key), comp)
            match = count_match(addr)
            if match > best:
                best = match
                c = "C" if comp else "U"
                print(f"  pos23=176, pos{pos2}={val2} [{c}]: {match} - {addr[:15]}...")

            if check_key(key, f"step3_23_176_{pos2}_{val2}"):
                exit()

print(f"Best two-byte: {best}")

# ============================================================================
# 3. Three-byte modifications
# ============================================================================
print("\n[3] Three-byte mods (focused)...")

# Focus on positions that might be important
focus = [0, 1, 19, 20, 31] + list(range(5))

for pos2 in focus:
    if pos2 == 23:
        continue
    for pos3 in focus:
        if pos3 in [23, pos2]:
            continue
        for val2 in range(0, 256, 4):  # Coarser search
            for val3 in range(0, 256, 4):
                key = key_23_176.copy()
                key[pos2] = val2
                key[pos3] = val3

                addr = privkey_to_address(bytes(key), True)
                match = count_match(addr)
                if match > best:
                    best = match
                    print(f"  pos23=176, {pos2}={val2}, {pos3}={val3}: {match} - {addr[:15]}...")

                if check_key(key, f"step3_3mod"):
                    exit()

print(f"Best three-byte: {best}")

# ============================================================================
# 4. Different divisors with step 3
# ============================================================================
print("\n[4] Step 3 with different divisors...")

for div in range(1, 50):
    indices = [(57 + i * 3) % 64 for i in range(32)]
    key = [shell[idx] // div % 256 for idx in indices]

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 5:
        print(f"  div{div}: {match} - {addr[:match+3]}...")

    if check_key(key, f"step3_div{div}"):
        exit()

# ============================================================================
# 5. Step 3 with multiplier at 39
# ============================================================================
print("\n[5] Step 3 with mult at 39...")

for mult in range(1, 100):
    shell_m = shell.copy()
    shell_m[39] *= mult

    indices = [(57 + i * 3) % 64 for i in range(32)]
    key = [shell_m[idx] // 7 % 256 for idx in indices]

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 5:
        print(f"  mult{mult}: {match} - {addr[:match+3]}...")

    if check_key(key, f"step3_mult{mult}"):
        exit()

# ============================================================================
# 6. Different start with step 3
# ============================================================================
print("\n[6] Different starts with step 3...")

for start in range(64):
    indices = [(start + i * 3) % 64 for i in range(32)]
    key = [shell[idx] // 7 % 256 for idx in indices]

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 5:
        print(f"  start{start}: {match} - {addr[:match+3]}...")

    # Also try single byte mods on each
    for pos in range(32):
        for val in range(256):
            key2 = key.copy()
            key2[pos] = val
            if check_key(key2, f"start{start}_step3_{pos}_{val}"):
                exit()

# ============================================================================
# 7. Combination of step and pairs
# ============================================================================
print("\n[7] Step 3 pairs approach...")

for step in [3, 6, 9]:
    indices = [(57 + i * step) % 64 for i in range(64)]

    for div in [7, 10, 14]:
        key = []
        for i in range(32):
            a = shell[indices[i*2]]
            b = shell[indices[i*2+1]]
            val = (a + b) // div % 256
            key.append(val)

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 5:
            print(f"  step{step} pairs div{div}: {match} - {addr[:match+3]}...")

        if check_key(key, f"step{step}_pairs_div{div}"):
            exit()

# ============================================================================
# 8. Using outer or inner with step 3
# ============================================================================
print("\n[8] Outer/inner with step 3...")

indices = [(57 + i * 3) % 64 for i in range(32)]

for div in [7, 10, 20, 50]:
    key_o = [outer[idx] // div % 256 for idx in indices]
    key_i = [inner[idx] // div % 256 for idx in indices]

    for k, name in [(key_o, f"outer_div{div}"), (key_i, f"inner_div{div}")]:
        addr = privkey_to_address(bytes(k), True)
        match = count_match(addr)
        if match >= 5:
            print(f"  {name}: {match} - {addr[:match+3]}...")

        if check_key(k, f"step3_{name}"):
            exit()

# ============================================================================
# 9. Exhaustive search near best candidate
# ============================================================================
print("\n[9] Exhaustive near best...")

# Start from pos23=176 and try 4-byte neighborhoods
import random
random.seed(42)

best_key = key_23_176.copy()
best_match = 10

for trial in range(100000):
    key = key_23_176.copy()

    # Modify 2-4 random bytes
    num_mods = random.randint(2, 4)
    positions = random.sample([p for p in range(32) if p != 23], num_mods)

    for pos in positions:
        key[pos] = random.randint(0, 255)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match > best_match:
        best_match = match
        best_key = key.copy()
        print(f"  Trial {trial}: {match} chars - {addr[:15]}...")

    if check_key(key, f"random_{trial}"):
        exit()

print(f"\nBest match: {best_match}")
print(f"Best key: {bytes(best_key).hex()}")

# ============================================================================
# 10. Try the "crypto" hint - what if bytes spell something?
# ============================================================================
print("\n[10] Byte spelling analysis...")

# The target is 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7
# "crypto" = [99, 114, 121, 112, 116, 111] in ASCII

crypto_bytes = [ord(c) for c in "crypto"]
print(f"'crypto' as bytes: {crypto_bytes}")

# Check if any shell values / div give these
for div in range(1, 20):
    matches = []
    for i, target_b in enumerate(crypto_bytes):
        for j in range(64):
            if shell[j] // div % 256 == target_b:
                matches.append((i, j, target_b))
                break

    if len(matches) == 6:
        print(f"  div{div}: All 'crypto' bytes found!")

# Maybe the key literally contains "crypto" somewhere?
for offset in range(26):  # Leave room for 6 bytes
    key = base_key.copy()
    for i, b in enumerate(crypto_bytes):
        key[offset + i] = b

    if check_key(key, f"crypto_at_{offset}"):
        exit()

print("\n" + "="*70)
print("Step 3 exploration complete")
print("="*70)
