"""
Deep search around the best candidates found.
Best so far: pos 13 val 50 gives 6 char match.
Also exploring step 46 (0x77 at position 1).
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
print("DEEP SEARCH")
print("="*70)

# ============================================================================
# 1. Explore around pos 13 val 50 (6 char match)
# ============================================================================
print("\n[1] Exploring around pos 13 val 50...")

indices = [(57 + i * 26) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]

# Set pos 13 to 50 and try second modifications
best_match = 6
key_13_50 = base_key.copy()
key_13_50[13] = 50

for pos2 in range(32):
    if pos2 == 13:
        continue
    for val2 in range(256):
        key = key_13_50.copy()
        key[pos2] = val2

        for comp in [True, False]:
            addr = privkey_to_address(bytes(key), comp)
            if addr:
                match = sum(1 for a, b in zip(addr, TARGET) if a == b)
                if match > best_match:
                    best_match = match
                    c = "C" if comp else "U"
                    print(f"  pos13=50, pos{pos2}={val2} [{c}]: {match} chars - {addr[:match+3]}...")

                if check_key(key, f"13_50_{pos2}_{val2}"):
                    exit()

print(f"Best with pos13=50: {best_match} chars")

# ============================================================================
# 2. Try all step values systematically with single-byte mods
# ============================================================================
print("\n[2] All steps with single-byte mods...")

best_overall = 0
for step in range(2, 64):
    indices = [(57 + i * step) % 64 for i in range(32)]
    base_key = [shell[idx] // 7 % 256 for idx in indices]

    for pos in range(32):
        for val in range(256):
            key = base_key.copy()
            key[pos] = val

            addr = privkey_to_address(bytes(key), True)
            if addr:
                match = sum(1 for a, b in zip(addr, TARGET) if a == b)
                if match > best_overall:
                    best_overall = match
                    print(f"  step{step} pos{pos}={val}: {match} chars - {addr[:match+3]}...")

            if check_key(key, f"step{step}_{pos}_{val}"):
                exit()

print(f"Best overall: {best_overall} chars")

# ============================================================================
# 3. Try different start positions (not just 57)
# ============================================================================
print("\n[3] Different start positions...")

for start in range(64):
    for step in [26, 2, 17, 7]:
        indices = [(start + i * step) % 64 for i in range(32)]
        base_key = [shell[idx] // 7 % 256 for idx in indices]

        # Check if first byte is meaningful
        if base_key[0] not in [0x28, 0x77]:
            continue

        addr = privkey_to_address(bytes(base_key), True)
        if addr:
            match = sum(1 for a, b in zip(addr, TARGET) if a == b)
            if match >= 3:
                print(f"  start{start} step{step}: {match} chars - {addr[:match+3]}...")

        if check_key(base_key, f"start{start}_step{step}"):
            exit()

# ============================================================================
# 4. The target starts with "1crypto" - what bytes produce "crypto"?
# ============================================================================
print("\n[4] Analyzing target prefix...")

# What hash160 prefix produces "1crypto"?
# The address "1crypto..." means the hash160 starts with a specific value
# Let's see what our base key produces and compare

base_key = [shell[idx] // 7 % 256 for idx in [(57 + i * 26) % 64 for i in range(32)]]
addr = privkey_to_address(bytes(base_key), True)
print(f"Base key address: {addr}")

# Decode target to see what we need
decoded = base58.b58decode(TARGET)
target_h160 = decoded[1:21]
print(f"Target hash160: {target_h160.hex()}")

# What does our base key produce?
from hashlib import sha256
privkey = bytes(base_key)
try:
    sk = ecdsa.SigningKey.from_string(privkey, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]
    sha = sha256(pubkey).digest()
    rip = hashlib.new('ripemd160')
    rip.update(sha)
    our_h160 = rip.digest()
    print(f"Our hash160:    {our_h160.hex()}")

    # How many bytes match at start?
    prefix_match = 0
    for i in range(20):
        if our_h160[i] == target_h160[i]:
            prefix_match = i + 1
        else:
            break
    print(f"Hash160 prefix match: {prefix_match} bytes")
except Exception as e:
    print(f"Error: {e}")

# ============================================================================
# 5. Try pairs formula with step pattern
# ============================================================================
print("\n[5] Pairs + step pattern...")

for step in [26, 17, 7, 2]:
    indices = [(57 + i * step) % 64 for i in range(64)]  # 64 indices for pairs

    # Pair them up
    for div in [7, 10]:
        key = []
        for i in range(32):
            a = shell[indices[i*2]]
            b = shell[indices[i*2 + 1]]
            val = (a + b) // div % 256
            key.append(val)

        addr = privkey_to_address(bytes(key), True)
        if addr:
            match = sum(1 for a, b in zip(addr, TARGET) if a == b)
            if match >= 3:
                print(f"  pairs step{step} div{div}: {match} chars - {addr[:match+3]}...")

        if check_key(key, f"pairs_step{step}_div{div}"):
            exit()

# ============================================================================
# 6. Combine outer/inner with shell in step pattern
# ============================================================================
print("\n[6] Combined values with step pattern...")

indices = [(57 + i * 26) % 64 for i in range(32)]

for div in [7, 10, 17]:
    # Use (outer - inner) which equals shell
    key1 = [(outer[idx] - inner[idx]) // div % 256 for idx in indices]
    if check_key(key1, f"outer_minus_inner_div{div}"):
        exit()

    # Use (outer + inner + shell) / 3
    key2 = [(outer[idx] + inner[idx] + shell[idx]) // (div * 3) % 256 for idx in indices]
    if check_key(key2, f"all_three_div{div*3}"):
        exit()

    # Use outer / div
    key3 = [outer[idx] // div % 256 for idx in indices]
    if check_key(key3, f"outer_only_div{div}"):
        exit()

    # Use inner / div
    key4 = [inner[idx] // div % 256 for idx in indices]
    if check_key(key4, f"inner_only_div{div}"):
        exit()

# ============================================================================
# 7. What if position 39 needs to be multiplied in the shell array first?
# ============================================================================
print("\n[7] Pre-multiply shell[39]...")

for mult in range(1, 100):
    shell_m = shell.copy()
    shell_m[39] *= mult

    indices = [(57 + i * 26) % 64 for i in range(32)]
    key = [shell_m[idx] // 7 % 256 for idx in indices]

    addr = privkey_to_address(bytes(key), True)
    if addr:
        match = sum(1 for a, b in zip(addr, TARGET) if a == b)
        if match >= 4:
            print(f"  mult{mult}: {match} chars - {addr[:match+3]}...")

    if check_key(key, f"premult_{mult}"):
        exit()

# ============================================================================
# 8. What if we need to add the multiplier to shell[39] instead?
# ============================================================================
print("\n[8] Add to shell[39]...")

for add in range(0, 10000, 7):
    shell_m = shell.copy()
    shell_m[39] += add

    indices = [(57 + i * 26) % 64 for i in range(32)]
    key = [shell_m[idx] // 7 % 256 for idx in indices]

    if check_key(key, f"add_{add}"):
        exit()

# ============================================================================
# 9. Bit-level XOR with constant
# ============================================================================
print("\n[9] XOR with constants...")

indices = [(57 + i * 26) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]

for xor_val in range(256):
    key = [b ^ xor_val for b in base_key]
    if check_key(key, f"xor_{xor_val}"):
        exit()

# ============================================================================
# 10. Progressive multiplier
# ============================================================================
print("\n[10] Progressive modifications...")

indices = [(57 + i * 26) % 64 for i in range(32)]

for mult in range(1, 20):
    key = []
    for i, idx in enumerate(indices):
        val = (shell[idx] * (mult + i % mult)) // 7 % 256
        key.append(val)

    if check_key(key, f"prog_mult_{mult}"):
        exit()

print("\n" + "="*70)
print("Deep search complete")
print("="*70)
