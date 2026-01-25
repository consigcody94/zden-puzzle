"""
Deep exploration of promising combinations:
1. F1: (Shell - Inner*X + 64) / X gives 0x77 at pos 2 (X=7) and pos 25 (X=64)
2. Snake pattern with m17/div7 gives 0x77 at pos 19

Let's explore combinations and also try brute-forcing some byte positions.
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
print("DEEP EXPLORATION")
print("="*70)

# ============================================================================
# Output the promising formulas
# ============================================================================
print("[1] Formula F1 (Shell - Inner*X + 64) / X...")

for X in [7, 64]:
    shell_m = shell.copy()
    inner_m = inner.copy()

    pairs = []
    for i in range(32):
        S = shell_m[i*2] + shell_m[i*2+1]
        I = inner_m[i*2] + inner_m[i*2+1]
        result = (S - I * X + 64) // X % 256
        pairs.append(result)

    print(f"  X={X}: {[hex(p) for p in pairs]}")
    print(f"  0x77 at: {[i for i, p in enumerate(pairs) if p == 0x77]}")
    check_key(pairs, f"F1_X{X}")

# ============================================================================
# Try combining F1 with multipliers
# ============================================================================
print("\n[2] F1 with multipliers at rect 39 and 52...")

for X in [7, 64]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            inner_m = inner.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53
            inner_m[39] *= mult40
            inner_m[52] *= mult53

            pairs = []
            for i in range(32):
                S = shell_m[i*2] + shell_m[i*2+1]
                I = inner_m[i*2] + inner_m[i*2+1]
                result = (S - I * X + 64) // X % 256
                pairs.append(result)

            has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  X={X} m{mult40}_{mult53}: 0x77 at {has_77}")
                if check_key(pairs, f"F1_X{X}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Try formula with both X=7 and X=64 for different halves
# ============================================================================
print("\n[3] Split formula: X=7 for first half, X=64 for second half...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        pairs = []
        for i in range(32):
            S = shell_m[i*2] + shell_m[i*2+1]
            I = inner_m[i*2] + inner_m[i*2+1]
            X = 7 if i < 16 else 64
            result = (S - I * X + 64) // X % 256
            pairs.append(result)

        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  Split m{mult40}_{mult53}: 0x77 at {has_77}")
            if check_key(pairs, f"F1_split_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Try snake pattern with formula
# ============================================================================
print("\n[4] Snake pattern with F1 formula...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        # Create snake ordering
        snake_shell = []
        snake_inner = []
        for row in range(8):
            if row % 2 == 0:
                for col in range(8):
                    snake_shell.append(shell_m[row * 8 + col])
                    snake_inner.append(inner_m[row * 8 + col])
            else:
                for col in range(7, -1, -1):
                    snake_shell.append(shell_m[row * 8 + col])
                    snake_inner.append(inner_m[row * 8 + col])

        for X in [7, 64]:
            pairs = []
            for i in range(32):
                S = snake_shell[i*2] + snake_shell[i*2+1]
                I = snake_inner[i*2] + snake_inner[i*2+1]
                result = (S - I * X + 64) // X % 256
                pairs.append(result)

            has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Snake X={X} m{mult40}_{mult53}: 0x77 at {has_77}")
                if check_key(pairs, f"F1_snake_X{X}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# What if we need to combine multiple 0x77 positions?
# ============================================================================
print("\n[5] Multiple 0x77 positions...")

# We found 0x77 at position 2 (X=7), 25 (X=64), and 19 (standard m17/div7)
# Maybe we need to use different formulas for different positions

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        # Try using X=7 for positions around 2, X=64 for positions around 25,
        # and standard div for position 19

        pairs = []
        for i in range(32):
            S = shell_m[i*2] + shell_m[i*2+1]
            I = inner_m[i*2] + inner_m[i*2+1]

            if i <= 5:  # Use X=7 formula
                result = (S - I * 7 + 64) // 7 % 256
            elif i >= 20:  # Use X=64 formula
                result = (S - I * 64 + 64) // 64 % 256
            else:  # Use standard division
                result = (S + S // 10) // 7 % 256

            pairs.append(result)

        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  Mixed m{mult40}_{mult53}: 0x77 at {has_77}")
            if check_key(pairs, f"mixed_formula_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Try the standard baseline but with different offsets
# ============================================================================
print("\n[6] Standard m17/div7 with byte offsets...")

shell_m = shell.copy()
shell_m[39] *= 17

base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Try adding/subtracting small values to each byte
for offset in range(-5, 6):
    pairs = [(b + offset) % 256 for b in base]
    if check_key(pairs, f"m17_div7_offset{offset}"):
        exit()

# Try XOR with common values
for xor_val in [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]:
    pairs = [b ^ xor_val for b in base]
    if check_key(pairs, f"m17_div7_xor{hex(xor_val)}"):
        exit()

# ============================================================================
# Brute force search: try modifying a few bytes
# ============================================================================
print("\n[7] Limited brute force: modify 1-2 bytes...")

shell_m = shell.copy()
shell_m[39] *= 17

base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Try changing one byte at a time
for pos in range(32):
    for val in range(256):
        pairs = base.copy()
        pairs[pos] = val
        if check_key(pairs, f"m17_div7_pos{pos}_val{val}"):
            exit()

print("  Single byte modification: no solution found")

# ============================================================================
# Try 2-byte modifications at key positions
# ============================================================================
print("\n[8] Two-byte modifications at key positions...")

key_positions = [0, 2, 19, 25, 31]  # First, 0x77 positions, last

for p1 in key_positions:
    for p2 in key_positions:
        if p1 >= p2:
            continue
        for v1 in [0x77, 0x00, 0xFF]:
            for v2 in [0x77, 0x00, 0xFF]:
                pairs = base.copy()
                pairs[p1] = v1
                pairs[p2] = v2
                if check_key(pairs, f"m17_div7_p{p1}v{v1}_p{p2}v{v2}"):
                    exit()

print("\nDeep exploration complete.")
print("\n" + "="*70)
print("Current best candidate key:")
print("="*70)
hex_key = ''.join(f'{p:02x}' for p in base)
print(f"Hex: {hex_key}")
print(f"Method: shell[39]*17, consecutive pairs, div 7, mod 256")
