"""
BREAKTHROUGH THINKING:

FIX = F(6) + I(9) + X(24) = 39 → RECT 40! (the 17px line rect!)

This CAN'T be a coincidence!

Also:
- Digit sums: 30 + 10 = 40 → also points to rect 40!
- 17 * 7 = 119 = 0x77

The mini-puzzle digits might define the PAIRING OFFSET for each byte:
09111819 = [0, 9, 1, 1, 1, 8, 1, 9] - offsets for bytes 0-7
11122111 = [1, 1, 1, 2, 2, 1, 1, 1] - offsets for bytes 8-15
(Then repeat for bytes 16-31)

If digit is the OFFSET from base pairing:
- Byte i: rect[i*2] + rect[i*2 + digit]
- 0 means consecutive (offset 1)
- 9 means skip to rect i*2 + 9
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
print("FIX DECODE - DEEP ANALYSIS")
print("="*70)
print("FIX = F(6) + I(9) + X(24) = 39 -> Rect 40!")
print("Digit sums: 30 + 10 = 40 -> Also points to Rect 40!")
print()

# The offset patterns from mini-puzzle
seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # Before FIX
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # After FIX

# Full 32-byte offset pattern (seq1 twice, then seq2 twice)
full_offset = seq1 + seq1 + seq2 + seq2  # 32 offsets

# Alternative: seq1 for first 16, seq2 for second 16
alt_offset = (seq1 * 2)[:16] + (seq2 * 2)[:16]

# ============================================================================
# Test 1: Digits as pairing offsets
# Byte i: rect[i*2] + rect[i*2 + offset] where offset = digit (0 means 1)
# ============================================================================
print("[1] Digits as pairing offsets (0->1)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64, 127]:
            for offset_pattern in [full_offset, alt_offset]:
                pairs = []
                for i in range(32):
                    offset = offset_pattern[i]
                    if offset == 0:
                        offset = 1  # 0 means consecutive (offset 1)
                    idx1 = i * 2
                    idx2 = (i * 2 + offset) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
                if has_77 or pairs[0] == 0x28:
                    pattern_name = "full" if offset_pattern == full_offset else "alt"
                    print(f"  {pattern_name} div{div} m{mult39}_{mult52}: first={hex(pairs[0])}, 0x77 at {has_77}")
                    if check_key(pairs, f"offset_{pattern_name}_div{div}_m{mult39}_{mult52}"):
                        exit()

# ============================================================================
# Test 2: Digits as direct rect indices for second element
# Byte i: rect[i*2] + rect[digit]
# ============================================================================
print("\n[2] Digits as direct rect indices...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            pairs = []
            all_digits = seq1 + seq2  # 16 digits
            for i in range(32):
                digit = all_digits[i % 16]
                idx1 = i * 2
                idx2 = digit  # Direct index
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  DirectIdx div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"directidx_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 3: Row/Column interpretation in 8x8 grid
# Digit tells which row to pick from each column
# ============================================================================
print("\n[3] Row/Column grid interpretation...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        # Read grid: for column c, pick row = digit[c] % 8
        for div in [7, 10, 64]:
            # First pass: columns 0-7 with seq1 rows
            # Second pass: columns 0-7 with seq2 rows
            indices = []
            for col in range(8):
                row = seq1[col] % 8
                indices.append(row * 8 + col)
            for col in range(8):
                row = seq2[col] % 8
                indices.append(row * 8 + col)
            # Repeat for 64 total
            indices = (indices * 4)[:64]

            pairs = []
            for i in range(32):
                idx1 = indices[i * 2] if i * 2 < len(indices) else i * 2
                idx2 = indices[i * 2 + 1] if i * 2 + 1 < len(indices) else i * 2 + 1
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77 or pairs[0] == 0x28:
                print(f"  RowCol div{div} m{mult39}_{mult52}: first={hex(pairs[0])}, 0x77 at {has_77}")
                if check_key(pairs, f"rowcol_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 4: The digits mod 8 as column indices
# ============================================================================
print("\n[4] Digits mod 8 as grid coordinates...")

# 09111819 mod 8 = [0, 1, 1, 1, 1, 0, 1, 1]
# 11122111 mod 8 = [1, 1, 1, 2, 2, 1, 1, 1]

seq1_mod8 = [d % 8 for d in seq1]
seq2_mod8 = [d % 8 for d in seq2]

print(f"  seq1 mod 8: {seq1_mod8}")
print(f"  seq2 mod 8: {seq2_mod8}")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            # Use seq1_mod8 for row offset, seq2_mod8 for col offset
            pairs = []
            for i in range(32):
                base_row = (i * 2) // 8
                base_col = (i * 2) % 8
                row_offset = seq1_mod8[i % 8]
                col_offset = seq2_mod8[i % 8]

                idx1 = ((base_row + row_offset) % 8) * 8 + base_col
                idx2 = base_row * 8 + ((base_col + col_offset) % 8)

                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  GridOffset div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"gridoffset_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 5: FIX = 39, so use rect 39 as anchor
# Pair each rect with rect 39!
# ============================================================================
print("\n[5] Every rect pairs with rect 39 (FIX point)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64, 127]:
            # Each byte i: rect[i*2] + rect[39]
            pairs = []
            for i in range(32):
                idx1 = i * 2
                val = (shell_m[idx1] + shell_m[39]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Anchor39 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"anchor39_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 6: Lightning = XOR before, Skull = subtract after
# First apply XOR to raw values, then divide, then subtract
# ============================================================================
print("\n[6] Lightning (XOR) then FIX (div) then Skull (subtract)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            for xor_val in [39, 40, 64, 0x77]:
                for sub_val in [0, 1, 10, 39]:
                    pairs = []
                    for i in range(32):
                        # Lightning: XOR the sum
                        raw = shell_m[i*2] + shell_m[i*2+1]
                        xored = raw ^ xor_val
                        # FIX: divide
                        fixed = xored // div
                        # Skull: subtract
                        result = (fixed - sub_val) % 256
                        pairs.append(result)

                    has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
                    if has_77 and pairs[0] == 0x28:
                        print(f"  XOR{xor_val}_div{div}_sub{sub_val} m{mult39}_{mult52}: first=0x28, 0x77 at {has_77}")
                        if check_key(pairs, f"xor{xor_val}_div{div}_sub{sub_val}_m{mult39}_{mult52}"):
                            exit()

# ============================================================================
# Test 7: Combine FIX=39 with digit offsets
# ============================================================================
print("\n[7] FIX=39 combined with digit offset pattern...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        all_digits = seq1 + seq2  # 16 digits

        for div in [7, 10, 64]:
            pairs = []
            for i in range(32):
                digit = all_digits[i % 16]
                # Base index is around 39 (FIX point), offset by digit
                idx1 = (39 + i) % 64
                idx2 = (39 + i + digit) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  FIX39_offset div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"fix39_offset_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 8: Sequence defines which rects go with which (pair matching)
# ============================================================================
print("\n[8] Sequence as pair matching pattern...")

# 09111819: positions where digit = 0,9,8 are "special"
# These are positions 0, 1, 5, 7 in the first sequence
# 11122111: positions where digit = 2 are "special" (positions 3, 4)

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            # Use digit value directly as second rect index offset from position
            pairs = []
            for i in range(32):
                digit = (seq1 + seq2)[i % 16]
                idx1 = i * 2
                # Second rect is at position determined by digit
                if digit == 0:
                    idx2 = idx1 + 1  # Consecutive
                elif digit == 9:
                    idx2 = (idx1 + 9) % 64  # Skip 9
                elif digit == 8:
                    idx2 = (idx1 + 8) % 64  # Skip 8 (next row)
                elif digit == 1:
                    idx2 = idx1 + 1  # Consecutive
                elif digit == 2:
                    idx2 = (idx1 + 2) % 64  # Skip 2
                else:
                    idx2 = idx1 + 1

                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77 or pairs[0] == 0x28:
                print(f"  PairMatch div{div} m{mult39}_{mult52}: first={hex(pairs[0])}, 0x77 at {has_77}")
                if check_key(pairs, f"pairmatch_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 9: Both multipliers are derived from FIX
# FIX=39, 17px line at rect 39, 6px line at rect 52
# What if 52 = 39 + 13? Or some other relationship?
# ============================================================================
print("\n[9] FIX relationship: 39 and 52...")

print(f"  Rect 39 (FIX): shell={shell[39]}, 17px line")
print(f"  Rect 52: shell={shell[52]}, 6px line")
print(f"  52 - 39 = 13")
print(f"  39 + 13 = 52")
print(f"  shell[39] / shell[52] = {shell[39] / shell[52]:.2f}")

# Maybe pair rect i with rect (i + 13)?
for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            pairs = []
            for i in range(32):
                idx1 = i
                idx2 = (i + 13) % 64  # Offset by 13 (52 - 39)
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Skip13 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"skip13_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 10: The divisor is derived from the sequences
# Digit sum 30 -> use 30, digit sum 10 -> use 10
# Or 30/10 = 3, try div 3
# ============================================================================
print("\n[10] Divisor 3 (from 30/10)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 3 % 256 for i in range(32)]
        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        print(f"  Div3 m{mult39}_{mult52}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"div3_m{mult39}_{mult52}"):
            exit()

print("\nFIX decode exploration complete.")
