"""
KEY INSIGHT: "consecutive" was CROSSED OUT!
The pairing is NOT [0+1, 2+3, 4+5...] but some other "following" pattern.

Mini-puzzle: 09111819 FIX 11122111
Could define the pairing pattern or coordinate offsets.

Formula: -I *X+ LXIV /x/
- Could be: (-1 * X + 64) / X or (Shell - Inner) * X + 64 / X
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
print("FOLLOWING (NOT CONSECUTIVE) PAIRING SOLVER")
print("="*70)
print("Key insight: 'consecutive' was crossed out!")
print("Mini-puzzle: 09111819 FIX 11122111")
print()

# ============================================================================
# Interpretation 1: Mini-puzzle defines offset pattern
# 09111819 = pairs (0,9), (1,1), (1,8), (1,9) as row/col in 8x8 grid
# ============================================================================
print("[1] Mini-puzzle as row/col offsets in 8x8 grid...")

# Grid layout: 8x8, rectangles numbered 0-63
# Rectangle at (row, col) = row * 8 + col

def idx_to_rowcol(idx):
    return (idx // 8, idx % 8)

def rowcol_to_idx(row, col):
    return (row % 8) * 8 + (col % 8)

# 09111819 as digit pairs: (0,9), (1,1), (1,8), (1,9)
# But 9 > 7, so maybe it's offset from current position
# Or maybe (0,9) means rect 0 pairs with rect 9

# 11122111 as digit pairs: (1,1), (1,2), (2,1), (1,1)

# Try: the numbers tell us which rectangle to pair with
# Pattern A: rect[i] pairs with rect[i + offset[i % 8]]

offsets_before = [0, 9, 1, 1, 1, 8, 1, 9]  # From 09111819
offsets_after = [1, 1, 1, 2, 2, 1, 1, 1]   # From 11122111

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Method: rect[i] + rect[i + offset] where offset cycles
            pairs = []
            for i in range(32):
                if i < 16:
                    offset = offsets_before[i % 8]
                else:
                    offset = offsets_after[(i - 16) % 8]

                idx1 = i
                idx2 = (i + offset) % 64

                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"offset_pattern_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 2: The sequence tells us explicit pairing indices
# 09, 11, 18, 19, 11, 12, 21, 11 are rectangle indices
# ============================================================================
print("\n[2] Mini-puzzle as explicit rectangle indices...")

# Parse as 2-digit numbers: 09, 11, 18, 19, 11, 12, 21, 11
explicit_indices = [9, 11, 18, 19, 11, 12, 21, 11]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Use explicit indices as a repeating pattern
            pairs = []
            for i in range(32):
                idx = explicit_indices[i % 8]
                partner = explicit_indices[(i + 1) % 8]

                val = (shell_m[idx] + shell_m[partner]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"explicit_idx_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 3: "Following" means column-wise or diagonal
# Instead of [0+1, 2+3, 4+5...], use [0+8, 1+9, 2+10...] (vertical)
# ============================================================================
print("\n[3] Following as vertical (column-wise) pairing...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Vertical pairing: rect[col] + rect[col + 8] for each row pair
            pairs = []
            for row in range(4):  # 4 row pairs
                for col in range(8):
                    idx1 = row * 16 + col  # Top rect
                    idx2 = row * 16 + col + 8  # Bottom rect
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"vertical_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Also try column-first ordering
            pairs = []
            for col in range(8):
                for row in range(4):
                    idx1 = row * 2 * 8 + col
                    idx2 = (row * 2 + 1) * 8 + col
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"col_first_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 4: "Following" with skip = 9 (diagonal?)
# Rect[0] + Rect[9], Rect[1] + Rect[10], etc.
# ============================================================================
print("\n[4] Following with skip = 9 (like the first mini-puzzle digit)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for skip in [9, 11, 18, 19]:  # Numbers from mini-puzzle
            for div in [7, 64, 127]:
                pairs = []
                for i in range(32):
                    idx1 = i
                    idx2 = (i + skip) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                if 119 in pairs:
                    if check_key(pairs, f"skip{skip}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Interpretation 5: First half pairs, second half pairs differently
# 09111819 for bytes 0-15, 11122111 for bytes 16-31
# ============================================================================
print("\n[5] Split pattern: different offsets for first/second half...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # First 16 bytes use indices from 09111819
            # Last 16 bytes use indices from 11122111
            pairs = []

            # First half: sequential with offset pattern from 09111819
            for i in range(16):
                digit = offsets_before[i % 8]
                idx1 = i * 2
                idx2 = i * 2 + digit
                if idx2 >= 64:
                    idx2 = idx2 % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            # Second half: sequential with offset pattern from 11122111
            for i in range(16):
                digit = offsets_after[i % 8]
                idx1 = 32 + i * 2
                if idx1 >= 64:
                    idx1 = idx1 % 64
                idx2 = idx1 + digit
                if idx2 >= 64:
                    idx2 = idx2 % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"split_offset_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 6: Formula as (-1 * 10 + 64) / x or variations
# -I could mean subtract Inner, *X could mean times 10
# ============================================================================
print("\n[6] Formula interpretation: (-I * 10 + 64) / x...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for x in [1, 7, 10, 64]:
            # (-I * 10 + 64) / x for each pair
            pairs = []
            for i in range(32):
                I = inner_m[i * 2] + inner_m[i * 2 + 1]
                result = (-I * 10 + 64) // x if x > 0 else 0
                pairs.append(abs(result) % 256)

            if 119 in pairs:
                if check_key(pairs, f"formula_neg_i_x{x}_m{mult40}_{mult53}"):
                    exit()

            # (Shell - Inner) * 10 + 64 / x = Shell*10 + 64/x (since S = O - I)
            pairs = []
            for i in range(32):
                S = shell_m[i * 2] + shell_m[i * 2 + 1]
                result = (S * 10 + 64) // max(x, 1)
                pairs.append(result % 256)

            if 119 in pairs:
                if check_key(pairs, f"formula_s10_64_x{x}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 7: The 17 and 6 pixel lines are multipliers
# Apply to rect 40 and 53, which gives the "fix"
# ============================================================================
print("\n[7] Apply 17 and 6 as multipliers to rects 39 and 52 (0-indexed)...")

for div in [7, 64, 127]:
    # The white lines are at rects 40 and 53 (1-indexed), so 39 and 52 (0-indexed)
    shell_m = shell.copy()
    shell_m[39] *= 17
    shell_m[52] *= 6

    # Now try different pairing patterns
    for skip in [1, 9, 11]:
        pairs = []
        for i in range(32):
            idx1 = i * 2
            idx2 = (i * 2 + skip) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // div % 256
            pairs.append(val)

        if 119 in pairs:
            pos = [j for j, v in enumerate(pairs) if v == 119]
            print(f"  Found 119 at {pos} with skip={skip}, div={div}")
            if check_key(pairs, f"m17_6_skip{skip}_div{div}"):
                exit()

# ============================================================================
# Interpretation 8: Reading direction from mini-puzzle
# 09111819 = start at rect 0, go to 9, then 11, then 18, then 19...
# ============================================================================
print("\n[8] Mini-puzzle as a path through the grid...")

# Path: 0 -> 9 -> 11 -> 18 -> 19 -> 11 -> 12 -> 21 -> 11 -> ...
path_steps = [0, 9, 11, 18, 19, 11, 12, 21, 11]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Build path by following the mini-puzzle pattern
            path = []
            current = 0
            for step in (path_steps * 10)[:64]:  # Repeat to fill 64 positions
                path.append(current)
                current = (current + step) % 64

            # Pair consecutive path elements
            pairs = []
            for i in range(32):
                idx1 = path[i * 2]
                idx2 = path[i * 2 + 1]
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"path_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Interpretation 9: Lightning = XOR, Skull = subtract
# Lightning above FIX: XOR before the fix operation
# Skull below FIX: subtract after the fix operation
# ============================================================================
print("\n[9] Lightning (XOR) above FIX, Skull (subtract) below...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            for xor_key in [0x77, 64, 119]:
                for sub_val in [0, 1, 64]:
                    pairs = []
                    for i in range(32):
                        # XOR the pair values (lightning)
                        xored = shell_m[i * 2] ^ shell_m[i * 2 + 1]
                        # FIX: divide by divisor
                        fixed = xored // div
                        # Skull: subtract
                        result = (fixed - sub_val) % 256
                        pairs.append(result)

                    if 119 in pairs:
                        if check_key(pairs, f"xor_fix_sub_div{div}_xk{xor_key}_sv{sub_val}_m{mult40}_{mult53}"):
                            exit()

# ============================================================================
# Interpretation 10: FIX means "fix" specific positions with 119
# The crossed-out consecutive might mean fix at non-consecutive positions
# ============================================================================
print("\n[10] FIX as setting specific byte positions to 119...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Fix positions from mini-puzzle: 0, 9, 11, 18, 19
            positions = [0, 9, 11, 18, 19]

            pairs = base.copy()
            for pos in positions:
                if pos < 32:
                    pairs[pos] = 119

            if check_key(pairs, f"fix_positions_div{div}_m{mult40}_{mult53}"):
                exit()

            # Also try with second sequence positions: 11, 12, 21
            positions2 = [11, 12, 21]
            pairs = base.copy()
            for pos in positions2:
                if pos < 32:
                    pairs[pos] = 119

            if check_key(pairs, f"fix_positions2_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Interpretation 11: Hex digit approach with "following" skip
# D1 and D2 are not consecutive, but skip by pattern
# ============================================================================
print("\n[11] Hex digit with following (skip) pattern...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for skip in [9, 11, 8]:  # Skip patterns from mini-puzzle
            for div in [64, 119, 128]:
                hex_digits = [s // div % 16 for s in shell_m]

                # Pair with skip
                pairs = []
                for i in range(32):
                    d1 = hex_digits[i]
                    d2 = hex_digits[(i + skip) % 64]
                    pairs.append(d1 * 16 + d2)

                if 0x77 in pairs:
                    if check_key(pairs, f"hex_skip{skip}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Interpretation 12: Interleaved pairing
# Take every other rectangle: [0, 2, 4...] pairs with [1, 3, 5...]
# ============================================================================
print("\n[12] Interleaved (odd/even) pairing...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Even indices pair with odd indices
            evens = [shell_m[i] for i in range(0, 64, 2)]  # 0, 2, 4, ...
            odds = [shell_m[i] for i in range(1, 64, 2)]   # 1, 3, 5, ...

            pairs = [(evens[i] + odds[i]) // div % 256 for i in range(32)]

            if 119 in pairs:
                if check_key(pairs, f"even_odd_div{div}_m{mult40}_{mult53}"):
                    exit()

            # First 32 with last 32
            first32 = shell_m[:32]
            last32 = shell_m[32:]

            pairs = [(first32[i] + last32[i]) // div % 256 for i in range(32)]

            if 119 in pairs:
                if check_key(pairs, f"first_last_div{div}_m{mult40}_{mult53}"):
                    exit()

print("\nFollowing pattern search complete.")
