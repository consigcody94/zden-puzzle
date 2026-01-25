"""
Try more formula variations based on: -I *X+ LXIV /x/

Possible interpretations:
1. (-I) * X + (LXIV / x) = (-Inner) * X + (64 / X)
2. (-I) * (X + LXIV) / x = (-Inner) * (X + 64) / X
3. ((-I) * X + LXIV) / x = ((-Inner) * X + 64) / X
4. -(I * X) + LXIV / x = -(Inner * X) + 64/X

Also: lightning = multiply/power, skull = subtract/negate
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
print("FORMULA VARIATIONS")
print("="*70)

# ============================================================================
# Formula interpretations with different values for X
# ============================================================================
print("[1] Various formula interpretations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        outer_m = outer.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53
        outer_m[39] *= mult40
        outer_m[52] *= mult53

        for X in [7, 10, 17, 64]:
            # Formula 1: (Shell - Inner*X + 64) / X
            pairs = []
            for i in range(32):
                S = shell_m[i*2] + shell_m[i*2+1]
                I = inner_m[i*2] + inner_m[i*2+1]
                result = (S - I * X + 64) // X % 256
                pairs.append(result)

            if 0x77 in pairs:
                print(f"  F1 X={X} m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"F1_X{X}_m{mult40}_{mult53}"):
                    exit()

            # Formula 2: (Outer - Inner*X + 64) / X
            pairs = []
            for i in range(32):
                O = outer_m[i*2] + outer_m[i*2+1]
                I = inner_m[i*2] + inner_m[i*2+1]
                result = (O - I * X + 64) // X % 256
                pairs.append(result)

            if 0x77 in pairs:
                print(f"  F2 X={X} m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"F2_X{X}_m{mult40}_{mult53}"):
                    exit()

            # Formula 3: (-Inner*X + 64) / X
            pairs = []
            for i in range(32):
                I = inner_m[i*2] + inner_m[i*2+1]
                result = abs((-I * X + 64) // X) % 256
                pairs.append(result)

            if 0x77 in pairs:
                if check_key(pairs, f"F3_X{X}_m{mult40}_{mult53}"):
                    exit()

            # Formula 4: Shell / X + 64 / X = (Shell + 64) / X
            pairs = []
            for i in range(32):
                S = shell_m[i*2] + shell_m[i*2+1]
                result = (S + 64) // X % 256
                pairs.append(result)

            if 0x77 in pairs:
                print(f"  F4 X={X} m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"F4_X{X}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Maybe X is the position or rect index
# ============================================================================
print("\n[2] X as position-dependent value...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            pairs = []
            for i in range(32):
                S = shell_m[i*2] + shell_m[i*2+1]
                X = i + 1  # Position-based X
                result = (S * X + 64) // divisor % 256
                pairs.append(result)

            if 0x77 in pairs:
                if check_key(pairs, f"posX_div{divisor}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Lightning = XOR, Skull = subtract after division
# ============================================================================
print("\n[3] Lightning (XOR pairs) then divide, then Skull (subtract)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            for sub in [0, 1, 64]:
                pairs = []
                for i in range(32):
                    # Lightning: XOR
                    xored = shell_m[i*2] ^ shell_m[i*2+1]
                    # Divide
                    divided = xored // divisor
                    # Skull: subtract
                    result = (divided - sub) % 256
                    pairs.append(result)

                if 0x77 in pairs:
                    if check_key(pairs, f"xor_div{divisor}_sub{sub}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Shell values arranged differently in the 8x8 grid
# ============================================================================
print("\n[4] Different grid arrangements...")

# Try reading the grid in different orders
for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            # Column-major order
            col_major = []
            for col in range(8):
                for row in range(8):
                    col_major.append(shell_m[row * 8 + col])

            pairs = [(col_major[i*2] + col_major[i*2+1]) // divisor % 256 for i in range(32)]
            if 0x77 in pairs:
                print(f"  ColMajor div{divisor} m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"colmajor_div{divisor}_m{mult40}_{mult53}"):
                    exit()

            # Snake pattern (alternating row directions)
            snake = []
            for row in range(8):
                if row % 2 == 0:
                    for col in range(8):
                        snake.append(shell_m[row * 8 + col])
                else:
                    for col in range(7, -1, -1):
                        snake.append(shell_m[row * 8 + col])

            pairs = [(snake[i*2] + snake[i*2+1]) // divisor % 256 for i in range(32)]
            if 0x77 in pairs:
                print(f"  Snake div{divisor} m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
                if check_key(pairs, f"snake_div{divisor}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# The digit sequence might define the reading order
# ============================================================================
print("\n[5] Mini-puzzle as reading order...")

seq = [0, 9, 1, 1, 1, 8, 1, 9, 1, 1, 1, 2, 2, 1, 1, 1]  # Combined sequence

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            # Use sequence as column offset for each row
            reordered = []
            for row in range(8):
                for col_offset in range(8):
                    col = (col_offset + seq[row % len(seq)]) % 8
                    reordered.append(shell_m[row * 8 + col])

            pairs = [(reordered[i*2] + reordered[i*2+1]) // divisor % 256 for i in range(32)]
            if 0x77 in pairs:
                if check_key(pairs, f"seq_reorder_div{divisor}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Try division by the shell ratio (839/118 = 7.1)
# ============================================================================
print("\n[6] Division by shell ratio...")

ratio_div = shell[39] // shell[52]  # = 7

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // ratio_div % 256 for i in range(32)]
        print(f"  Ratio div ({ratio_div}) m{mult40}_{mult53}: 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
        if check_key(pairs, f"ratio_div_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# What if we need to hash the result?
# ============================================================================
print("\n[7] SHA256 of computed bytes...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // divisor % 256 for i in range(32)]
            hashed = hashlib.sha256(bytes(pairs)).digest()

            if check_key(list(hashed), f"sha256_div{divisor}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Nibble-based operations
# ============================================================================
print("\n[8] Nibble operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // divisor % 256 for i in range(32)]

            # Swap nibbles
            nibble_swapped = [((b & 0x0F) << 4) | ((b >> 4) & 0x0F) for b in pairs]
            if 0x77 in nibble_swapped:
                if check_key(nibble_swapped, f"nibble_swap_div{divisor}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Rotate each byte
# ============================================================================
print("\n[9] Bit rotation...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for divisor in [7, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // divisor % 256 for i in range(32)]

            for rot in range(1, 8):
                rotated = [((b << rot) | (b >> (8 - rot))) & 0xFF for b in pairs]
                if 0x77 in rotated:
                    if check_key(rotated, f"rot{rot}_div{divisor}_m{mult40}_{mult53}"):
                        exit()

print("\nFormula variations complete.")
