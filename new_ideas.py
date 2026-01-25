"""
New ideas for solving the puzzle.

Key insight: shell[39]/7 = 119 = 0x77 and shell[57]/7 = 40 = 0x28
These are EXACT - maybe they're meant to be at specific positions.

What if:
- Byte 0 should be 0x28 (from position 57)
- Some other byte should be 0x77 (from position 39)
- The rest follows a pattern
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
print("NEW IDEAS")
print("="*70)

# ============================================================================
# 1. Single rectangles with positions 39 and 57 as anchors
# ============================================================================
print("\n[1] Single rect keys with 39/57 anchors...")

# Build key using single rects, with 57 at position 0 and 39 at various positions
for pos_77 in range(1, 32):
    for div in [7]:
        key = []
        for i in range(32):
            if i == 0:
                key.append(shell[57] // div % 256)  # 0x28
            elif i == pos_77:
                key.append(shell[39] // div % 256)  # 0x77
            else:
                # Use sequential single rects
                rect_idx = i if i < pos_77 else i - 1
                if rect_idx >= 57:
                    rect_idx += 1
                if rect_idx >= 39:
                    rect_idx += 1
                rect_idx = rect_idx % 64
                key.append(shell[rect_idx] // div % 256)

        if check_key(key, f"anchor_{pos_77}"):
            exit()

# ============================================================================
# 2. The formula "-I *X+ LXIV /x/" interpretation
# ============================================================================
print("\n[2] Formula interpretation...")

# -I = subtract inner, *X = multiply by X (24 or 10?), + LXIV = add 64, /x/ = divide by x
# Try: (-inner + outer*X + 64) / divisor

for X in [10, 24]:
    for div in [7, 10, 17, 64]:
        key = []
        for i in range(32):
            val = (-inner[i] + outer[i] * X + 64) // div % 256
            if val < 0:
                val = (val % 256 + 256) % 256
            key.append(val)

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 3:
            print(f"  X={X} div={div}: {match} chars - {addr[:15]}...")

        if check_key(key, f"formula_X{X}_div{div}"):
            exit()

# ============================================================================
# 3. Maybe the key uses alternating operations
# ============================================================================
print("\n[3] Alternating operations...")

for div in [7, 10]:
    # Alternate between add and subtract
    key = []
    for i in range(32):
        if i % 2 == 0:
            val = (shell[i*2] + shell[i*2+1]) // div % 256
        else:
            val = abs(shell[i*2] - shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Alt add/sub div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"alt_addsub_div{div}"):
        exit()

# ============================================================================
# 4. Use the two-digit sequence as rectangle indices directly
# ============================================================================
print("\n[4] Two-digit as rect indices...")

# 09111819 11122111 -> indices 09, 11, 18, 19, 11, 12, 21, 11
two_digit = [9, 11, 18, 19, 11, 12, 21, 11]

for div in [7, 10]:
    # Use these 8 indices, then repeat or continue
    key = []
    for i in range(32):
        idx = two_digit[i % 8]
        key.append(shell[idx] // div % 256)

    addr = privkey_to_address(bytes(key), True)
    print(f"  2-digit cycle div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"2digit_cycle_div{div}"):
        exit()

# Extended: use first 8, then second 8 different
seq1_2d = [9, 11, 18, 19]
seq2_2d = [11, 12, 21, 11]

for div in [7, 10]:
    key = []
    for i in range(32):
        if i < 16:
            idx = seq1_2d[i % 4]
        else:
            idx = seq2_2d[(i-16) % 4]
        key.append(shell[idx] // div % 256)

    addr = privkey_to_address(bytes(key), True)
    print(f"  Split 2-digit div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"split_2digit_div{div}"):
        exit()

# ============================================================================
# 5. Roman numeral LXIV = 64 as modulus
# ============================================================================
print("\n[5] LXIV (64) as modulus...")

for div in [1, 7, 10]:
    key = [(shell[i*2] + shell[i*2+1]) // div % 64 for i in range(32)]
    # Scale to full byte range
    key = [k * 4 for k in key]

    addr = privkey_to_address(bytes(key), True)
    print(f"  mod64 *4 div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"mod64_div{div}"):
        exit()

# ============================================================================
# 6. Combine FIX with step patterns
# ============================================================================
print("\n[6] FIX + step patterns...")

shell_m = shell.copy()
shell_m[39] *= 17

for start in [0, 39, 57]:
    for step in [2, 3, 17, 26]:
        indices = [(start + i * step) % 64 for i in range(32)]
        key = [shell_m[idx] // 7 % 256 for idx in indices]

        addr = privkey_to_address(bytes(key), True)
        match = count_match(addr)
        if match >= 3:
            print(f"  FIX start{start} step{step}: {match} chars")

        if check_key(key, f"fix_step_{start}_{step}"):
            exit()

# ============================================================================
# 7. What if we need to use outer-inner (which equals shell) differently?
# ============================================================================
print("\n[7] Component arithmetic...")

for div in [7, 10]:
    # (outer + inner) / div - this is different from shell
    key = [(outer[i] + inner[i]) // div % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    print(f"  (O+I) div{div}: match {count_match(addr)}")
    if check_key(key, f"oi_sum_div{div}"):
        exit()

    # outer / div
    key = [outer[i] // div % 256 for i in range(32)]
    if check_key(key, f"outer_div{div}"):
        exit()

    # inner / div
    key = [inner[i] // div % 256 for i in range(32)]
    if check_key(key, f"inner_div{div}"):
        exit()

# ============================================================================
# 8. Intensive search with best base (10 char match)
# ============================================================================
print("\n[8] Building on 10-char match base...")

# Step-3 with pos23=176 gave 10 char match
indices = [(57 + i * 3) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]
base_key[23] = 176

print(f"Base: {bytes(base_key).hex()}")
addr = privkey_to_address(bytes(base_key), True)
print(f"Base addr: {addr}")
print(f"Target:    {TARGET}")

# Try systematic 2-byte modifications
best = 10
for p1 in range(32):
    for v1 in range(256):
        key = base_key.copy()
        key[p1] = v1

        for comp in [True, False]:
            addr = privkey_to_address(bytes(key), comp)
            match = count_match(addr)
            if match > best:
                best = match
                c = "C" if comp else "U"
                print(f"  p{p1}={v1} [{c}]: {match} chars - {addr[:20]}...")

            if check_key(key, f"step3_mod_{p1}_{v1}"):
                exit()

print(f"Best single-byte on step3: {best}")

# ============================================================================
# 9. Random intensive on step3 base
# ============================================================================
print("\n[9] Random on step3 base...")

random.seed(999)
for trial in range(500000):
    key = base_key.copy()

    # Modify 2-4 positions
    num_mods = random.randint(2, 4)
    positions = random.sample(range(32), num_mods)
    for pos in positions:
        key[pos] = random.randint(0, 255)

    for comp in [True, False]:
        addr = privkey_to_address(bytes(key), comp)
        match = count_match(addr)
        if match > best:
            best = match
            c = "C" if comp else "U"
            print(f"  Trial {trial} [{c}]: {match} chars - {addr[:20]}...")

        if check_key(key, f"step3_random_{trial}"):
            exit()

    if trial % 100000 == 0 and trial > 0:
        print(f"  ...{trial} trials, best: {best}")

print(f"\nBest random: {best}")

# ============================================================================
# 10. Try reversing the key
# ============================================================================
print("\n[10] Key transformations...")

# Reverse
key = base_key[::-1]
if check_key(key, "step3_reversed"):
    exit()

# Byte-swap pairs
key = []
for i in range(0, 32, 2):
    key.append(base_key[i+1])
    key.append(base_key[i])
if check_key(key, "step3_byteswap"):
    exit()

# Complement
key = [255 - b for b in base_key]
if check_key(key, "step3_complement"):
    exit()

# XOR with 0xFF
key = [b ^ 0xFF for b in base_key]
if check_key(key, "step3_xor_ff"):
    exit()

print("\n" + "="*70)
print("New ideas complete")
print("="*70)
