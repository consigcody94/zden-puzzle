"""
Rethinking the puzzle from scratch.

Key observations:
1. shell[39]/7 = 119 = 0x77 EXACTLY
2. shell[57]/7 = 40 = 0x28 EXACTLY
3. These are the ONLY values that divide evenly by 7 and give "nice" numbers

What if the puzzle is telling us:
- Byte 0 should be 0x28 (from rect 57)
- Some byte should be 0x77 (from rect 39)

And the mini-puzzle "09111819 FIX 11122111" tells us:
- Which OTHER positions need special handling
- Or which rectangles to use

The two-digit interpretation: 09, 11, 18, 19, 11, 12, 21, 11
These could be rectangle indices for specific byte positions!
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
print("RETHINKING THE PUZZLE")
print("="*70)

# ============================================================================
# 1. Find ALL shell values that divide evenly by various numbers
# ============================================================================
print("\n[1] Perfect divisibility analysis...")

for div in [7, 10, 17]:
    perfect = []
    for i in range(64):
        if shell[i] % div == 0:
            result = shell[i] // div
            perfect.append((i, shell[i], result))

    if perfect:
        print(f"\n  Perfect division by {div}:")
        for idx, val, result in perfect:
            print(f"    shell[{idx}] = {val} / {div} = {result}")

# ============================================================================
# 2. What values in shell give exactly 0x28 or 0x77 when divided?
# ============================================================================
print("\n[2] Finding 0x28 and 0x77 producers...")

for target_byte in [0x28, 0x77]:
    print(f"\n  Target byte {hex(target_byte)} ({target_byte}):")
    for div in range(1, 50):
        for i in range(64):
            if shell[i] // div % 256 == target_byte:
                if shell[i] % div == 0:  # Perfect division
                    print(f"    shell[{i}]={shell[i]} / {div} = {shell[i]//div} -> 0x{target_byte:02x} (EXACT)")
                elif shell[i] // div < 256:  # Result is the target without mod
                    print(f"    shell[{i}]={shell[i]} / {div} = {shell[i]//div} -> 0x{target_byte:02x}")

# ============================================================================
# 3. Two-digit indices interpretation
# ============================================================================
print("\n[3] Two-digit indices from mini-puzzle...")

# 09111819 FIX 11122111
# Two-digit: 09, 11, 18, 19, 11, 12, 21, 11
two_digit = [9, 11, 18, 19, 11, 12, 21, 11]
print(f"Two-digit indices: {two_digit}")

# What if these are the rectangle indices for bytes 0-7?
for div in [7, 10]:
    key = [0] * 32
    for i, idx in enumerate(two_digit):
        key[i] = shell[idx] // div % 256

    # Fill rest from consecutive pairs
    for i in range(8, 32):
        key[i] = (shell[i*2] + shell[i*2+1]) // div % 256

    addr = privkey_to_address(bytes(key), True)
    print(f"  First 8 from indices, div{div}: {addr}, match: {count_match(addr)}")
    if check_key(key, f"2digit_first8_div{div}"):
        exit()

# ============================================================================
# 4. What if the digits are positions to SKIP?
# ============================================================================
print("\n[4] Digits as skip positions...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]

# Skip positions indicated by the sequence
for div in [7, 10]:
    skip = set()
    pos = 0
    for d in seq1 + seq2:
        pos += d
        skip.add(pos)

    # Build key skipping those positions
    key = []
    idx = 0
    for i in range(32):
        while idx in skip:
            idx += 1
        if idx < 64:
            key.append(shell[idx] // div % 256)
            idx += 1
        else:
            key.append(0)

    if len(key) == 32:
        addr = privkey_to_address(bytes(key), True)
        print(f"  Skip pattern div{div}: match {count_match(addr)}")
        if check_key(key, f"skip_div{div}"):
            exit()

# ============================================================================
# 5. Cumulative sums as indices
# ============================================================================
print("\n[5] Cumulative sums as indices...")

cumsum = []
total = 0
for d in seq1 + seq2:
    total += d
    cumsum.append(total % 64)

print(f"Cumulative sums: {cumsum}")

for div in [7, 10]:
    # Use cumsum as rectangle indices
    key = [shell[idx] // div % 256 for idx in cumsum]
    # Extend to 32 bytes
    key = (key * 2)[:32]

    addr = privkey_to_address(bytes(key), True)
    print(f"  Cumsum indices div{div}: match {count_match(addr)}")
    if check_key(key, f"cumsum_div{div}"):
        exit()

# ============================================================================
# 6. The formula hint "-I *X+ LXIV /x/"
# ============================================================================
print("\n[6] Formula hint interpretation...")

# Maybe it's: -I means subtract index, *X means multiply by X value,
# + LXIV means add 64, /x/ means divide by some x

# Or: shell[i] = -inner + outer*X + 64 / divisor
# Let's verify: shell = outer - inner, so -inner + outer = shell + 2*inner - outer?

# Try: (-inner * X + outer) / 64
for X in [1, 10, 17]:
    key = []
    for i in range(32):
        val = (-inner[i*2] * X + outer[i*2]) // 64 % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  Formula X={X}: match {match}")
    if check_key(key, f"formula_X{X}"):
        exit()

# ============================================================================
# 7. Maybe each triplet (outer, inner, shell) encodes differently
# ============================================================================
print("\n[7] Three-component encoding...")

for a_coef in [1, -1]:
    for b_coef in [1, -1]:
        for c_coef in [1, -1]:
            for div in [7, 10, 17, 64]:
                key = []
                for i in range(32):
                    val = (a_coef * outer[i] + b_coef * inner[i] + c_coef * shell[i]) // div % 256
                    key.append(val)

                addr = privkey_to_address(bytes(key), True)
                match = count_match(addr)
                if match >= 4:
                    print(f"  [{a_coef},{b_coef},{c_coef}] div{div}: match {match}")
                if check_key(key, f"3comp_{a_coef}_{b_coef}_{c_coef}_div{div}"):
                    exit()

# ============================================================================
# 8. What if position 39 is special because 39 = F+I+X?
# ============================================================================
print("\n[8] Position 39 encoding variants...")

# F=6, I=9, X=24 in letter positions
# Also: 3+9 = 12, 39 in octal, etc.

# Try using shell[39] in different ways
val_39 = shell[39]  # 839
print(f"shell[39] = {val_39}")
print(f"  /7 = {val_39/7} -> {val_39//7}")
print(f"  /10 = {val_39/10} -> {val_39//10}")
print(f"  % 256 = {val_39 % 256}")

# What if byte 19 (the position we found 0x77) is special because 1+9=10?
# And byte 0 is 0x28 = 40 because digit sums = 30+10=40?

# ============================================================================
# 9. Direct byte values from shell modulo
# ============================================================================
print("\n[9] Direct modulo values...")

for mod in [256, 128, 64]:
    key = [shell[i] % mod for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    print(f"  shell[0:32] mod {mod}: match {match}")
    if check_key(key, f"direct_mod{mod}"):
        exit()

    key = [shell[32+i] % mod for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    print(f"  shell[32:64] mod {mod}: match {match}")
    if check_key(key, f"direct32_mod{mod}"):
        exit()

# ============================================================================
# 10. XOR between consecutive rectangles
# ============================================================================
print("\n[10] XOR between consecutive...")

for div in [1, 7, 10]:
    key = []
    for i in range(32):
        if div == 1:
            val = (shell[i*2] ^ shell[i*2+1]) % 256
        else:
            val = ((shell[i*2] ^ shell[i*2+1]) // div) % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    print(f"  XOR div{div}: match {match}")
    if check_key(key, f"xor_div{div}"):
        exit()

# ============================================================================
# 11. Product of consecutive mod 256
# ============================================================================
print("\n[11] Products...")

for div in [1, 100, 1000, 10000]:
    key = []
    for i in range(32):
        val = (shell[i*2] * shell[i*2+1]) // div % 256
        key.append(val)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  Product div{div}: match {match}")
    if check_key(key, f"product_div{div}"):
        exit()

# ============================================================================
# 12. GCD of consecutive pairs
# ============================================================================
print("\n[12] GCD approach...")

import math

key = []
for i in range(32):
    g = math.gcd(shell[i*2], shell[i*2+1])
    key.append(g % 256)

addr = privkey_to_address(bytes(key), True)
print(f"  GCD: match {count_match(addr)}, key: {bytes(key[:8]).hex()}...")
if check_key(key, "gcd"):
    exit()

# ============================================================================
# 13. What if we use all 64 rects and take every other byte?
# ============================================================================
print("\n[13] All 64 rects, every other...")

for div in [7, 10]:
    key64 = [shell[i] // div % 256 for i in range(64)]

    # Take every other
    key = key64[::2]
    if check_key(key, f"every_other_div{div}"):
        exit()

    # Take odd positions
    key = key64[1::2]
    if check_key(key, f"odd_div{div}"):
        exit()

print("\n" + "="*70)
print("Rethink complete")
print("="*70)
