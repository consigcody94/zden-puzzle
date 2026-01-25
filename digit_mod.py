"""
Direct interpretation of digit sequence as byte modifications.

09111819 FIX 11122111

What if this means:
- At position 0, use value from rect 9
- At position 1, use value from rect 11
- etc.

Or what if it's XOR/ADD instructions?
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
print("DIGIT SEQUENCE AS BYTE MODIFICATIONS")
print("="*70)

# Base key with FIX
shell_m = shell.copy()
shell_m[39] *= 17
base_key = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

print(f"Base key: {bytes(base_key).hex()}")
print(f"Base addr: {privkey_to_address(bytes(base_key), True)}")

# ============================================================================
# 1. Two-digit interpretation: positions to modify
# ============================================================================
print("\n[1] Two-digit as positions...")

# 09111819 11122111 -> 09, 11, 18, 19, 11, 12, 21, 11
two_digit = [9, 11, 18, 19, 11, 12, 21, 11]
print(f"Two-digit positions: {two_digit}")

# Try setting these positions to specific values
for target_val in [0x28, 0x77, 0, 255]:
    key = base_key.copy()
    for pos in two_digit:
        if pos < 32:
            key[pos] = target_val

    addr = privkey_to_address(bytes(key), True)
    print(f"  Set to {hex(target_val)}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"set_positions_{hex(target_val)}"):
        exit()

# ============================================================================
# 2. Digits as XOR values
# ============================================================================
print("\n[2] Digits as XOR...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

for scale in [1, 7, 10, 17]:
    key = base_key.copy()
    for i in range(32):
        digit = all_digits[i % 16]
        key[i] = key[i] ^ (digit * scale)
        key[i] = key[i] % 256

    addr = privkey_to_address(bytes(key), True)
    print(f"  XOR scale {scale}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"xor_scale_{scale}"):
        exit()

# ============================================================================
# 3. Digits as byte swaps
# ============================================================================
print("\n[3] Digit-based swaps...")

# Swap byte i with byte (i + digit)
for wrap in [True, False]:
    key = base_key.copy()
    for i in range(16):
        digit = all_digits[i]
        if digit > 0:
            j = (i + digit) % 32 if wrap else min(i + digit, 31)
            key[i], key[j] = key[j], key[i]

    addr = privkey_to_address(bytes(key), True)
    w = "wrap" if wrap else "nowrap"
    print(f"  Swap {w}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"swap_{w}"):
        exit()

# ============================================================================
# 4. Specific positions from the sequence
# ============================================================================
print("\n[4] Specific position assignments...")

# The sequence might tell us which rect to use at each position
# 0-9-1-1-1-8-1-9 for first 8 bytes
# 1-1-1-2-2-1-1-1 for next 8 bytes

for div in [7, 10]:
    key = []

    # First 8 bytes: use rects 0, 9, 10, 11, 12, 20, 21, 30
    cumsum = 0
    for d in seq1:
        cumsum += d
        key.append(shell[cumsum % 64] // div % 256)

    # Next 8 bytes: continue cumsum
    for d in seq2:
        cumsum += d
        key.append(shell[cumsum % 64] // div % 256)

    # Remaining 16 bytes: normal pairs
    for i in range(16, 32):
        key.append((shell[i*2] + shell[i*2+1]) // div % 256)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Cumsum first 16 div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"cumsum16_div{div}"):
        exit()

# ============================================================================
# 5. Each digit tells which value source to use
# ============================================================================
print("\n[5] Digit selects source...")

# 0 = shell, 1 = outer, 2 = inner, 8 = shell*17, 9 = average
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

for div in [7, 10]:
    key = []
    for i in range(32):
        digit = all_digits[i % 16]
        if digit == 0:
            val = shell[i] // div % 256
        elif digit == 1:
            val = outer[i] // div % 256
        elif digit == 2:
            val = inner[i] // div % 256
        elif digit == 8:
            val = (shell[i] * 17) // div % 256
        elif digit == 9:
            val = (outer[i] + inner[i] + shell[i]) // (div * 3) % 256
        else:
            val = (shell[i*2 % 64] + shell[(i*2+1) % 64]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Source select div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"source_select_div{div}"):
        exit()

# ============================================================================
# 6. Literal interpretation: 09 11 18 19 are byte values
# ============================================================================
print("\n[6] Literal byte values...")

# Maybe 09111819 11122111 are the actual bytes (or part of key)
literal = [0x09, 0x11, 0x18, 0x19, 0x11, 0x12, 0x21, 0x11]

key = literal + base_key[8:]
addr = privkey_to_address(bytes(key), True)
print(f"  Literal first 8: {addr}, match: {count_match(addr)}")
if check_key(key, "literal_first8"):
    exit()

# Or as 4-byte chunks
key = [0x09, 0x11, 0x18, 0x19] + base_key[4:20] + [0x11, 0x12, 0x21, 0x11] + base_key[24:]
addr = privkey_to_address(bytes(key), True)
print(f"  Literal split: {addr}, match: {count_match(addr)}")
if check_key(key, "literal_split"):
    exit()

# ============================================================================
# 7. FIX position special treatment
# ============================================================================
print("\n[7] FIX position variations...")

# FIX = 39, and the key has 32 bytes, so position 39 in shell array affects pair 19
# What if we treat position 19 specially?

for special_val in range(256):
    key = base_key.copy()
    key[19] = special_val

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 5:
        print(f"  pos19={special_val}: {match} chars - {addr[:15]}...")

    if check_key(key, f"pos19_{special_val}"):
        exit()

# ============================================================================
# 8. Three-byte exhaustive around known good
# ============================================================================
print("\n[8] Three-byte exhaustive (sampled)...")

best = 0
import random
random.seed(42)

for trial in range(100000):
    key = base_key.copy()

    # Pick 3 positions
    positions = random.sample(range(32), 3)
    for pos in positions:
        key[pos] = random.randint(0, 255)

    for comp in [True, False]:
        addr = privkey_to_address(bytes(key), comp)
        match = count_match(addr)
        if match > best:
            best = match
            c = "C" if comp else "U"
            print(f"  Trial {trial} [{c}]: {match} chars - {addr[:15]}...")

        if check_key(key, f"3byte_{trial}"):
            exit()

print(f"\nBest 3-byte: {best}")

# ============================================================================
# 9. Analyze the target hash160 more
# ============================================================================
print("\n[9] Working backwards from target...")

decoded = base58.b58decode(TARGET)
h160 = list(decoded[1:21])
print(f"Target h160: {bytes(h160).hex()}")
print(f"First few bytes: {h160[:5]}")

# The h160 starts with [6, 200, 71, 151, ...]
# Can we find shell patterns that give these?

for i, target_byte in enumerate(h160[:10]):
    for div in range(1, 30):
        for idx in range(64):
            if shell[idx] // div % 256 == target_byte:
                print(f"  h160[{i}]={target_byte}: shell[{idx}]//{div}")
                break
        else:
            continue
        break

print("\n" + "="*70)
print("Digit modification analysis complete")
print("="*70)
