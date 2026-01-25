"""
Explore the rectangle walk approach more thoroughly.
Walk from 53 with div 7 gave 5 char match.
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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

print("="*70)
print("WALK EXPLORATION")
print("="*70)

# ============================================================================
# 1. Analyze the walk from 53
# ============================================================================
print("\n[1] Walk from 53 analysis...")

start = 53
div = 7
key = []
pos = start
walk_sequence = []
for i in range(32):
    key.append(shell[pos] // div % 256)
    walk_sequence.append(pos)
    digit = all_digits[i % 16]
    pos = (pos + digit + 1) % 64

print(f"Walk sequence: {walk_sequence}")
print(f"Key: {bytes(key).hex()}")
addr = privkey_to_address(bytes(key), True)
print(f"Address: {addr}")
print(f"Target:  {TARGET}")
print(f"Matches: {count_match(addr)}")

# ============================================================================
# 2. Try modifications on this base
# ============================================================================
print("\n[2] Modifications on walk-53...")

best = 5
for pos_mod in range(32):
    for val in range(256):
        key_test = key.copy()
        key_test[pos_mod] = val

        for comp in [True, False]:
            addr = privkey_to_address(bytes(key_test), comp)
            match = count_match(addr)
            if match > best:
                best = match
                c = "C" if comp else "U"
                print(f"  pos{pos_mod}={val} [{c}]: {match} chars - {addr[:15]}...")

            if check_key(key_test, f"walk53_mod_{pos_mod}_{val}"):
                exit()

print(f"Best single-byte mod: {best}")

# ============================================================================
# 3. Different walk patterns
# ============================================================================
print("\n[3] Different walk patterns...")

best_overall = 0
for start in range(64):
    for add_offset in [0, 1, 2]:  # Different ways to interpret +1
        for div in [7, 10]:
            key = []
            pos = start
            for i in range(32):
                key.append(shell[pos] // div % 256)
                digit = all_digits[i % 16]
                pos = (pos + digit + add_offset) % 64

            addr = privkey_to_address(bytes(key), True)
            match = count_match(addr)
            if match > best_overall:
                best_overall = match
                print(f"  start{start} off{add_offset} div{div}: {match} chars - {addr[:15]}...")

            if check_key(key, f"walk_{start}_{add_offset}_{div}"):
                exit()

print(f"Best walk pattern: {best_overall}")

# ============================================================================
# 4. Walk with no-repeat (skip visited)
# ============================================================================
print("\n[4] Walk with no repeats...")

for start in range(64):
    for div in [7, 10]:
        key = []
        pos = start
        visited = set()
        for i in range(32):
            # Skip to next unvisited
            attempts = 0
            while pos in visited and attempts < 64:
                pos = (pos + 1) % 64
                attempts += 1

            if attempts >= 64:
                break

            visited.add(pos)
            key.append(shell[pos] // div % 256)
            digit = all_digits[i % 16]
            pos = (pos + digit + 1) % 64

        if len(key) == 32:
            if check_key(key, f"norepeat_{start}_{div}"):
                exit()

# ============================================================================
# 5. Value-based walk (next position based on current value)
# ============================================================================
print("\n[5] Value-based walk...")

for start in range(64):
    for div in [7, 10]:
        key = []
        pos = start
        for i in range(32):
            val = shell[pos] // div % 256
            key.append(val)
            # Next position is current value mod 64
            pos = val % 64

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 4:
            print(f"  Value walk from {start} div{div}: {match} chars")

        if check_key(key, f"valuewalk_{start}_{div}"):
            exit()

# ============================================================================
# 6. Digit-controlled divisor
# ============================================================================
print("\n[6] Digit controls divisor...")

for start in range(64):
    key = []
    pos = start
    for i in range(32):
        digit = all_digits[i % 16]
        if digit == 0:
            div = 7
        else:
            div = digit + 6  # 7, 8, 9, 10, ...
        key.append(shell[pos] // div % 256)
        pos = (pos + digit + 1) % 64

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 4:
        print(f"  Digit-div from {start}: {match} chars")

    if check_key(key, f"digitdiv_{start}"):
        exit()

# ============================================================================
# 7. Shell value chains (value points to next index)
# ============================================================================
print("\n[7] Shell value chains...")

for start in range(64):
    for div in [7, 10, 17]:
        key = []
        pos = start
        for i in range(32):
            key.append(shell[pos] // div % 256)
            pos = shell[pos] % 64

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 4:
            print(f"  Chain from {start} div{div}: {match} chars")

        if check_key(key, f"chain_{start}_{div}"):
            exit()

# ============================================================================
# 8. Combined approach: walk + FIX at 39
# ============================================================================
print("\n[8] Walk + FIX combination...")

for mult in [17, 7, 10]:
    shell_m = shell.copy()
    shell_m[39] *= mult

    for start in range(64):
        for div in [7, 10]:
            key = []
            pos = start
            for i in range(32):
                key.append(shell_m[pos] // div % 256)
                digit = all_digits[i % 16]
                pos = (pos + digit + 1) % 64

            addr = privkey_to_address(bytes(key), True)
            match = count_match(addr)
            if match >= 5:
                print(f"  Walk{start} mult{mult} div{div}: {match} chars")

            if check_key(key, f"walkmult_{start}_{mult}_{div}"):
                exit()

# ============================================================================
# 9. Two-phase walk
# ============================================================================
print("\n[9] Two-phase walk...")

for start1 in range(64):
    for start2 in range(64):
        if start1 == start2:
            continue

        for div in [7, 10]:
            key = []

            # Phase 1: first 16 bytes from walk starting at start1
            pos = start1
            for i in range(16):
                key.append(shell[pos] // div % 256)
                digit = seq1[i % 8]
                pos = (pos + digit + 1) % 64

            # Phase 2: last 16 bytes from walk starting at start2
            pos = start2
            for i in range(16):
                key.append(shell[pos] // div % 256)
                digit = seq2[i % 8]
                pos = (pos + digit + 1) % 64

            if check_key(key, f"twophase_{start1}_{start2}_{div}"):
                exit()

# ============================================================================
# 10. Random exploration around best candidates
# ============================================================================
print("\n[10] Random exploration...")

# Start with walk-53 base
start = 53
key_base = []
pos = start
for i in range(32):
    key_base.append(shell[pos] // 7 % 256)
    digit = all_digits[i % 16]
    pos = (pos + digit + 1) % 64

random.seed(42)
best = 5
for trial in range(200000):
    key = key_base.copy()

    # Modify 1-3 random positions
    num_mods = random.randint(1, 3)
    positions = random.sample(range(32), num_mods)
    for p in positions:
        key[p] = random.randint(0, 255)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match > best:
        best = match
        print(f"  Trial {trial}: {match} chars - {addr[:15]}...")

    if check_key(key, f"random_{trial}"):
        exit()

    # Also try uncompressed
    addr = privkey_to_address(bytes(key), False)
    match = count_match(addr)
    if match > best:
        best = match
        print(f"  Trial {trial} UNCOMP: {match} chars - {addr[:15]}...")

print(f"\nBest random: {best}")

print("\n" + "="*70)
print("Walk exploration complete")
print("="*70)
