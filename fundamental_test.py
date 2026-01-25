"""
The key structure is right but address is wrong.
Let's test more fundamental variations:
1. No multiplier at all
2. Different positions for the multiplier
3. Maybe the shell values need to be interpreted differently
4. Maybe we need to use outer/inner instead of shell
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

print("="*70)
print("FUNDAMENTAL VARIATIONS")
print("="*70)

# ============================================================================
# 1. No multiplier - just raw shell values
# ============================================================================
print("\n[1] Raw shell values, no multiplier...")

for div in range(1, 20):
    pairs = []
    for i in range(32):
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        pairs.append(val)

    if check_key(pairs, f"raw_div{div}"):
        exit()

print("  Raw shell: no solution")

# ============================================================================
# 2. Try all combinations of multiplier position and value
# ============================================================================
print("\n[2] All multiplier positions and values...")

for pos in range(64):
    for mult in range(2, 25):
        shell_m = shell.copy()
        shell_m[pos] *= mult

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if check_key(pairs, f"pos{pos}_mult{mult}_div{div}"):
                exit()

print("  All positions: no solution")

# ============================================================================
# 3. Try using ONLY outer values (ignore inner/shell)
# ============================================================================
print("\n[3] Only outer values...")

for mult in [1, 17]:
    outer_m = outer.copy()
    if mult > 1:
        outer_m[39] *= mult

    for div in range(5, 50, 5):
        pairs = []
        for i in range(32):
            val = (outer_m[i*2] + outer_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  Outer mult{mult} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"outer_m{mult}_d{div}"):
                exit()

# ============================================================================
# 4. Try using ONLY inner values
# ============================================================================
print("\n[4] Only inner values...")

for mult in [1, 17]:
    inner_m = inner.copy()
    if mult > 1:
        inner_m[39] *= mult

    for div in range(5, 50, 5):
        pairs = []
        for i in range(32):
            val = (inner_m[i*2] + inner_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  Inner mult{mult} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"inner_m{mult}_d{div}"):
                exit()

# ============================================================================
# 5. Maybe the rectangle VALUES are indices into some larger table?
# ============================================================================
print("\n[5] Shell values as indices...")

# Create a table: shell values mod 256
table = [s % 256 for s in shell]
print(f"Table (shell mod 256): {table[:10]}...")

# Use indices based on position
pairs = [table[i] for i in range(32)]
if check_key(pairs, "shell_mod256"):
    exit()

# ============================================================================
# 6. What if we need to hash the concatenated shell values?
# ============================================================================
print("\n[6] Hash-based approaches...")

# Concatenate all shell values as bytes
all_shells = b''.join(s.to_bytes(2, 'big') for s in shell)
h = hashlib.sha256(all_shells).digest()
if check_key(list(h), "sha256_of_shells"):
    exit()

# With multiplier
shell_m = shell.copy()
shell_m[39] *= 17
all_shells = b''.join(s.to_bytes(2, 'big') for s in shell_m)
h = hashlib.sha256(all_shells).digest()
if check_key(list(h), "sha256_of_shells_m17"):
    exit()

# ============================================================================
# 7. What if the private key is the sha256 of something simpler?
# ============================================================================
print("\n[7] SHA256 of simple combinations...")

# SHA256 of "09111819FIX11122111"
h = hashlib.sha256(b"09111819FIX11122111").digest()
if check_key(list(h), "sha256_minipuzzle"):
    exit()

# SHA256 of rectangle data in various formats
h = hashlib.sha256(b"cryptoGeCRiTzVgxBQcKFFjSVydN1GW7").digest()
if check_key(list(h), "sha256_address_suffix"):
    exit()

# ============================================================================
# 8. Try with different orderings of rectangles
# ============================================================================
print("\n[8] Different rectangle orderings...")

# Reverse order
for div in [7, 10]:
    pairs = []
    for i in range(32):
        idx1 = 63 - i * 2
        idx2 = 63 - i * 2 - 1
        if idx2 >= 0:
            val = (shell[idx1] + shell[idx2]) // div % 256
        else:
            val = shell[idx1] // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Reversed div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"reversed_div{div}"):
            exit()

# Column-major in 8x8 grid
grid = [shell[row * 8 + col] for row in range(8) for col in range(8)]
col_major = []
for col in range(8):
    for row in range(8):
        col_major.append(grid[row * 8 + col])

for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = (col_major[i*2] + col_major[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Column-major div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"colmajor_div{div}"):
            exit()

# ============================================================================
# 9. What if the puzzle uses a specific constant offset?
# ============================================================================
print("\n[9] Constant offsets...")

shell_m = shell.copy()
shell_m[39] *= 17

for offset in range(-100, 101):
    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1] + offset) // 7 % 256
        pairs.append(val)

    if pairs[0] == 0x28 and 0x77 in pairs:
        if check_key(pairs, f"offset_{offset}"):
            exit()

print("  Offsets: no solution")

# ============================================================================
# 10. Brute force: try 3-byte modifications on best key
# ============================================================================
print("\n[10] Three-byte modification (limited)...")

shell_m = shell.copy()
shell_m[39] *= 17
base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Only modify bytes at positions not 0 or 19
test_positions = [1, 5, 10, 15, 20, 25, 31]

count = 0
for p1 in test_positions:
    for p2 in test_positions:
        for p3 in test_positions:
            if p1 >= p2 or p2 >= p3:
                continue
            for v1 in range(0, 256, 32):
                for v2 in range(0, 256, 32):
                    for v3 in range(0, 256, 32):
                        pairs = base.copy()
                        pairs[p1] = v1
                        pairs[p2] = v2
                        pairs[p3] = v3
                        if check_key(pairs, f"3byte_{p1}_{p2}_{p3}"):
                            exit()
                        count += 1

print(f"  Checked {count} three-byte combinations: no solution")

# ============================================================================
# 11. What if the key needs to be inverted or complemented?
# ============================================================================
print("\n[11] Bit inversions...")

pairs = [255 - b for b in base]
if check_key(pairs, "inverted"):
    exit()

pairs = [b ^ 0xFF for b in base]
if check_key(pairs, "xor_ff"):
    exit()

pairs = [b ^ 0x77 for b in base]
if check_key(pairs, "xor_77"):
    exit()

pairs = [b ^ 0x28 for b in base]
if check_key(pairs, "xor_28"):
    exit()

# ============================================================================
# 12. What about using the digit sums differently?
# ============================================================================
print("\n[12] Digit sum variations...")

# 30 and 10 as byte positions
pairs = base.copy()
pairs[30] = 0x77  # Force
pairs[10] = 0x28  # Force
if check_key(pairs, "force_30_10"):
    exit()

# 30 and 10 as XOR values
pairs = base.copy()
for i in range(32):
    if i < 16:
        pairs[i] ^= 30
    else:
        pairs[i] ^= 10
if check_key(pairs, "xor_30_10"):
    exit()

print("\n" + "="*70)
print("Fundamental tests complete")
print("="*70)
print(f"\nBest key structure found:")
print(f"Key: {bytes(base).hex()}")
print(f"First: 0x{base[0]:02x}, Byte 19: 0x{base[19]:02x}")
print(f"Address: {privkey_to_address(bytes(base), True)}")
print(f"Target:  {TARGET}")
