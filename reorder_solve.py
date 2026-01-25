"""
Fresh approach: What if the digit sequences tell us the ORDER to read rectangles?

09111819 -> positions 0, 9, 11, 18, 19
11122111 -> positions 11, 12, 21, 11 (with some repeat)

Or maybe they're telling us to READ in a specific pattern...

Also try: the "fix" might mean we need to fix/correct certain bytes
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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]

print("="*70)
print("REORDERING AND NEW PATTERNS")
print("="*70)

# ============================================================================
# 1. Interpret 09111819 as positions to read from
# ============================================================================
print("\n[1] 09111819 as read positions...")

# Parse as: 09, 11, 18, 19 (two-digit numbers)
positions1 = [9, 11, 18, 19]
positions2 = [11, 12, 21, 11]

print(f"Positions set 1: {positions1}")
print(f"Positions set 2: {positions2}")

shell_m = shell.copy()
shell_m[39] *= 17

# Use these as special positions
for div in [7, 10]:
    pairs = []
    for i in range(32):
        # Normal consecutive pairs
        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
        pairs.append(val)

    # Swap values at these positions with some other values
    if check_key(pairs, f"base_div{div}"):
        exit()

# ============================================================================
# 2. Maybe 09 11 18 19 and 11 12 21 11 are rect indices to pair specially
# ============================================================================
print("\n[2] Special rect pairs from digit groups...")

# Pair rects: (9,11), (18,19), (11,12), (21,11)?
special_pairs = [(9, 11), (18, 19), (11, 12), (21, 11)]
print(f"Special pairs: {special_pairs}")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    # First 28 bytes from consecutive pairs
    for i in range(28):
        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
        pairs.append(val)
    # Last 4 bytes from special pairs
    for p1, p2 in special_pairs:
        val = (shell_m[p1] + shell_m[p2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Special pairs div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"special_pairs_div{div}"):
            exit()

# ============================================================================
# 3. Maybe the numbers are read as: 0-9-1-1-1-8-1-9 then 1-1-1-2-2-1-1-1
#    And each number tells us how many rects to skip
# ============================================================================
print("\n[3] Cumulative skip pattern...")

all_digits = seq1 + seq2

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    pos = 0
    for i in range(32):
        digit = all_digits[i % 16]
        skip = digit if digit > 0 else 1

        # Get value from current position
        idx1 = pos % 64
        idx2 = (pos + 1) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

        # Move by skip amount
        pos += skip

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Cumulative skip div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"cumul_skip_div{div}"):
            exit()

# ============================================================================
# 4. What if we need to read in a spiral or zigzag through 8x8 grid?
# ============================================================================
print("\n[4] 8x8 grid traversal patterns...")

# Create 8x8 grid
grid = [[shell[row*8 + col] for col in range(8)] for row in range(8)]

# Multiply rect 39 (row 4, col 7)
grid[4][7] *= 17

# Zigzag read
def zigzag_read():
    result = []
    for row in range(8):
        if row % 2 == 0:
            for col in range(8):
                result.append(grid[row][col])
        else:
            for col in range(7, -1, -1):
                result.append(grid[row][col])
    return result

zigzag = zigzag_read()
for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = (zigzag[i*2] + zigzag[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Zigzag div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"zigzag_div{div}"):
            exit()

# Spiral read (outside to inside)
def spiral_read():
    result = []
    top, bottom, left, right = 0, 7, 0, 7
    while len(result) < 64:
        # Top row
        for col in range(left, right + 1):
            if len(result) < 64:
                result.append(grid[top][col])
        top += 1
        # Right column
        for row in range(top, bottom + 1):
            if len(result) < 64:
                result.append(grid[row][right])
        right -= 1
        # Bottom row
        for col in range(right, left - 1, -1):
            if len(result) < 64:
                result.append(grid[bottom][col])
        bottom -= 1
        # Left column
        for row in range(bottom, top - 1, -1):
            if len(result) < 64:
                result.append(grid[row][left])
        left += 1
    return result

spiral = spiral_read()
for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = (spiral[i*2] + spiral[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Spiral div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"spiral_div{div}"):
            exit()

# ============================================================================
# 5. What if "following" means we follow from one rect to the next
#    based on some property of the current rect?
# ============================================================================
print("\n[5] Following based on rect properties...")

shell_m = shell.copy()
shell_m[39] *= 17

# Follow pattern: next index = current value mod 64
for start in [0, 39, 52]:
    for div in [7, 10]:
        pairs = []
        indices = []
        idx = start
        for i in range(64):
            indices.append(idx)
            idx = shell_m[idx] % 64

        # Use first 64 indices to compute 32 bytes
        for i in range(32):
            val = (shell_m[indices[i*2]] + shell_m[indices[i*2+1]]) // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  Follow from {start} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"follow_{start}_div{div}"):
                exit()

# ============================================================================
# 6. What if digits tell us ROW and COLUMN in 8x8?
#    seq1 might be rows, seq2 might be columns
# ============================================================================
print("\n[6] Digit sequences as row/column indices...")

# Create grid again with mult
grid = [[shell[row*8 + col] for col in range(8)] for row in range(8)]
grid[4][7] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(8):
        row = seq1[i] % 8
        col = seq2[i] % 8
        val = grid[row][col] // div % 256
        pairs.append(val)

    # Only 8 bytes, try expanding
    pairs4 = pairs * 4
    has_77 = [j for j,p in enumerate(pairs4) if p==0x77]
    if has_77:
        print(f"  Row/Col x4 div{div}: 0x77 at {has_77}")
        if check_key(pairs4, f"rowcol_x4_div{div}"):
            exit()

# ============================================================================
# 7. What if we need to combine shell, outer, inner differently?
# ============================================================================
print("\n[7] Different combinations of shell/outer/inner...")

for div in [7, 10]:
    # Try: (outer - inner) * sign based on digit
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        sign = 1 if digit % 2 == 0 else -1
        idx = i * 2
        diff = (outer[idx] - inner[idx]) * sign + (outer[idx+1] - inner[idx+1])
        val = abs(diff) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Signed diff div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"signed_diff_div{div}"):
            exit()

# ============================================================================
# 8. Brute force: try all possible multipliers for rect 39
# ============================================================================
print("\n[8] Brute force rect 39 multiplier...")

for mult in range(1, 30):
    shell_m = shell.copy()
    shell_m[39] *= mult

    for div in [7, 10]:
        pairs = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"mult{mult}_div{div}"):
            exit()

# ============================================================================
# 9. What if there's a second multiplier at a different position?
# ============================================================================
print("\n[9] Two multipliers...")

# Try multipliers at positions hinted by digits
for pos in [9, 11, 18, 19, 21]:
    for mult_pos in [7, 17]:
        for mult_39 in [1, 17]:
            shell_m = shell.copy()
            shell_m[39] *= mult_39
            shell_m[pos] *= mult_pos

            for div in [7, 10]:
                pairs = []
                for i in range(32):
                    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                    pairs.append(val)

                if check_key(pairs, f"mult_pos{pos}_{mult_pos}_m39_{mult_39}_div{div}"):
                    exit()

# ============================================================================
# 10. What if 09111819 is actually meant to be read as a hex value?
# ============================================================================
print("\n[10] Hex interpretations...")

# 0x09111819 as a seed?
import struct

seed = 0x09111819
# Use it to XOR or shift the key

shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    base.append(val)

# XOR with seed bytes
seed_bytes = struct.pack('>I', seed)  # 4 bytes
for pattern in [seed_bytes, seed_bytes * 8]:
    pairs = []
    for i in range(32):
        pairs.append(base[i] ^ pattern[i % len(pattern)])
    if check_key(pairs, f"xor_seed_{len(pattern)}"):
        exit()

# Same for second sequence
seed2 = 0x11122111
seed2_bytes = struct.pack('>I', seed2)
for pattern in [seed2_bytes, seed2_bytes * 8]:
    pairs = []
    for i in range(32):
        pairs.append(base[i] ^ pattern[i % len(pattern)])
    if check_key(pairs, f"xor_seed2_{len(pattern)}"):
        exit()

print("\n" + "="*70)
print("Exploration complete, no solution found")
print("="*70)
print(f"\nBase key: {bytes(base).hex()}")
