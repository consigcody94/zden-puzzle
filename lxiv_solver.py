"""
LXIV = 64 (Roman numeral!)
FIX not FIN
Lightning bolt = XOR
Skull = subtract/negate

Formula: -I *X+ LXIV /x/
- Subtract I (1)
- Multiply by X (10) and add
- LXIV = 64 (divisor!)
- /x/ = divide or absolute value
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
print("LXIV = 64 SOLVER")
print("="*70)
print("Formula interpretation: -I *X+ LXIV /x/")
print("  -I = subtract 1")
print("  *X+ = multiply by 10, add")
print("  LXIV = 64 (divisor)")
print("  /x/ = divide/absolute value")
print()

# ============================================================================
# PRIMARY: Divisor 64 with various multipliers
# ============================================================================
print("[1] DIVISOR 64 - Primary search...")

for mult40 in [1, 17, 7]:
    for mult53 in [1, 6, 7]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Basic: (a + b) / 64
        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 64 % 256 for i in range(32)]
        if 119 in pairs:
            pos = [i for i, v in enumerate(pairs) if v == 119]
            print(f"  m{mult40}_{mult53}: 119 at positions {pos}")
        if check_key(pairs, f"div64_m{mult40}_{mult53}"):
            exit()

        # With -1 (subtract I)
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 64 - 1) % 256 for i in range(32)]
        if check_key(pairs, f"div64_minus1_m{mult40}_{mult53}"):
            exit()

        # Subtract 1 before divide
        pairs = [((shell_m[i*2] + shell_m[i*2+1] - 1)) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"minus1_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Using the full formula: -I *X+ LXIV /x/
# ============================================================================
print("\n[2] Full formula interpretation...")

# -I *X+ could mean: (sum - 1) * 10 + something
# LXIV = 64
# /x/ = divide by some x or absolute value

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # ((sum - 1) * 10 + sum) / 64
        pairs = [((shell_m[i*2] + shell_m[i*2+1] - 1) * 10 + (shell_m[i*2] + shell_m[i*2+1])) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"formula1_m{mult40}_{mult53}"):
            exit()

        # (sum * 10 - 1) / 64
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 10 - 1) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"times10_minus1_div64_m{mult40}_{mult53}"):
            exit()

        # |sum - something| / 64  (absolute value interpretation of /x/)
        for sub_val in [1, 10, 64, 100]:
            pairs = [abs((shell_m[i*2] + shell_m[i*2+1]) - sub_val) // 64 % 256 for i in range(32)]
            if check_key(pairs, f"abs_sub{sub_val}_div64_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Lightning bolt = XOR with 64
# ============================================================================
print("\n[3] XOR operations (lightning bolt)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # XOR with 64
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 64) ^ 64 for i in range(32)]
        pairs = [p % 256 for p in pairs]
        if check_key(pairs, f"xor64_m{mult40}_{mult53}"):
            exit()

        # XOR the two values, then divide by 64
        pairs = [(shell_m[i*2] ^ shell_m[i*2+1]) // 64 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  XOR pair div64 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"xor_pair_div64_m{mult40}_{mult53}"):
            exit()

        # Sum divided by 64, then XOR with position
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 64) ^ i for i in range(32)]
        pairs = [p % 256 for p in pairs]
        if check_key(pairs, f"div64_xor_pos_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Skull = subtraction/difference
# ============================================================================
print("\n[4] Subtraction operations (skull)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Difference instead of sum, divided by 64
        pairs = [abs(shell_m[i*2] - shell_m[i*2+1]) // 64 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  Diff div64 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"diff_div64_m{mult40}_{mult53}"):
            exit()

        # For smaller divisors with difference
        for div in [1, 2, 4, 8, 16, 32]:
            pairs = [abs(shell_m[i*2] - shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"diff_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# FIX could mean repair/correct something
# ============================================================================
print("\n[5] FIX interpretations...")

# Maybe FIX means we need to fix/adjust certain bytes
# The sequence 09111819 could indicate which positions to fix

seq = [0, 9, 1, 1, 1, 8, 1, 9]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        base = [(shell_m[i*2] + shell_m[i*2+1]) // 64 % 256 for i in range(32)]

        # Fix positions indicated by sequence
        for fix_val in [119, 0x77, 64]:
            pairs = base.copy()
            for i, s in enumerate(seq):
                if s < 32:
                    pairs[s] = fix_val
            if check_key(pairs, f"fix_seq_{fix_val}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# 09111819 and 11122111 as paired operations
# ============================================================================
print("\n[6] Sequence pair operations...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # seq1 for first half, seq2 for second half as offsets
        pairs = []
        for i in range(32):
            if i < 16:
                offset = seq1[i % 8]
            else:
                offset = seq2[(i-16) % 8]

            idx1 = i * 2
            idx2 = (i * 2 + 1 + offset) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // 64 % 256
            pairs.append(val)

        if 119 in pairs:
            if check_key(pairs, f"seq_halves_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Roman numerals throughout: I=1, X=10, L=50, V=5, IV=4
# ============================================================================
print("\n[7] Roman numeral operations...")

# -I = -1, *X = *10, + = add, LXIV = 64
# Full formula: ((sum - 1) * 10 + something) / 64

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Interpret as: ((-1 * 10) + LXIV) = -10 + 64 = 54
        # Or: -(1 * 10) + 64 = 54
        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 54 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  Div 54 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"div54_m{mult40}_{mult53}"):
            exit()

        # Or: -1 * 10 + 64 / x = some operation
        # Try: sum / (64 - 10 + 1) = sum / 55
        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 55 % 256 for i in range(32)]
        if check_key(pairs, f"div55_m{mult40}_{mult53}"):
            exit()

        # Or: (sum - I) * X / LXIV = (sum - 1) * 10 / 64
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) - 1) * 10 // 64 % 256 for i in range(32)]
        if check_key(pairs, f"minus1_times10_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# The squiggle /x/ could be floor division or modulo
# ============================================================================
print("\n[8] Floor division and modulo with 64...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Modulo 64 (not divide)
        pairs = [(shell_m[i*2] + shell_m[i*2+1]) % 64 for i in range(32)]
        if check_key(pairs, f"mod64_m{mult40}_{mult53}"):
            exit()

        # Mod 64 then scale up
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) % 64) * 2 for i in range(32)]
        if check_key(pairs, f"mod64_times2_m{mult40}_{mult53}"):
            exit()

        # Mod 64 + some offset
        for offset in [64, 55, 119]:
            pairs = [((shell_m[i*2] + shell_m[i*2+1]) % 64 + offset) % 256 for i in range(32)]
            if check_key(pairs, f"mod64_plus{offset}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Maybe 64 rectangles / 64 = 1 byte per rect
# ============================================================================
print("\n[9] One byte per rectangle...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # First 32 rectangles only
        pairs = [shell_m[i] // 64 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  First 32 div64 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"first32_div64_m{mult40}_{mult53}"):
            exit()

        # Last 32 rectangles
        pairs = [shell_m[i+32] // 64 % 256 for i in range(32)]
        if check_key(pairs, f"last32_div64_m{mult40}_{mult53}"):
            exit()

        # Every other rectangle
        pairs = [shell_m[i*2] // 64 % 256 for i in range(32)]
        if check_key(pairs, f"evens_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# LXIV could also mean "64 rects" arranged differently
# ============================================================================
print("\n[10] 8x8 grid with div 64...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Sum rows, divide by 64
        pairs = []
        for row in range(8):
            row_sum = sum(shell_m[row*8:(row+1)*8])
            # 4 bytes per row
            pairs.append((row_sum >> 24) % 256)
            pairs.append((row_sum >> 16) % 256)
            pairs.append((row_sum >> 8) % 256)
            pairs.append(row_sum % 256)

        if check_key(pairs[:32], f"rowsum_bytes_m{mult40}_{mult53}"):
            exit()

        # Column sums
        pairs = []
        for col in range(8):
            col_sum = sum(shell_m[col + row*8] for row in range(8))
            pairs.append((col_sum >> 24) % 256)
            pairs.append((col_sum >> 16) % 256)
            pairs.append((col_sum >> 8) % 256)
            pairs.append(col_sum % 256)

        if check_key(pairs[:32], f"colsum_bytes_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Combining all elements: XOR (lightning), subtract (skull), div 64
# ============================================================================
print("\n[11] Combined lightning + skull + LXIV...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # (a XOR b) - something, divided by 64
        for sub in [0, 1, 10]:
            pairs = [((shell_m[i*2] ^ shell_m[i*2+1]) - sub) // 64 % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"xor_sub{sub}_div64_m{mult40}_{mult53}"):
                    exit()

        # Subtract then XOR with 64
        pairs = [(abs(shell_m[i*2] - shell_m[i*2+1]) // 64) ^ 64 for i in range(32)]
        pairs = [p % 256 for p in pairs]
        if check_key(pairs, f"diff_div64_xor64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Try all nearby divisors around 64
# ============================================================================
print("\n[12] Divisors near 64...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in range(56, 73):  # 56 to 72
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                pos = [i for i, v in enumerate(pairs) if v == 119]
                if check_key(pairs, f"div{div}_m{mult40}_{mult53}"):
                    exit()

print("\nLXIV solver complete.")
print("No solution found yet.")
