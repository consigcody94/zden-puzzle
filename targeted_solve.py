"""
Targeted solver using mini-puzzle insights more directly
09111819 FIN 11122111
|-I xN+ LHIU /x?

LHIU = 12, 8, 9, 21
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
print("TARGETED SOLVER - MINI PUZZLE INSIGHTS")
print("="*70)

# LHIU values from symbol positions
L, H, I, U = 12, 8, 9, 21

# Mini puzzle sequences
seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # 09111819
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # 11122111

# ============================================================================
# Approach 1: Use seq1/seq2 as offsets for pairing
# ============================================================================
print("\n[1] Sequence-based pairing offsets...")

for mult40 in [1, 17]:
    for mult53 in [1, 6, 7]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64, 128]:
            # Use seq1 and seq2 as pairing offsets
            pairs = []
            for i in range(32):
                off1 = seq1[i % 8]
                off2 = seq2[i % 8]
                idx1 = (i * 2 + off1) % 64
                idx2 = (i * 2 + 1 + off2) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"seq_offset_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 2: LHIU as weights or divisors
# ============================================================================
print("\n[2] LHIU as operation parameters...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # LHIU as weights: L*a + H*b, I*a + U*b, etc.
        for w1, w2 in [(L, H), (I, U), (L, U), (H, I), (L, I), (H, U)]:
            for div in [64, 128, 256, 512]:
                pairs = [(shell_m[i*2] * w1 + shell_m[i*2+1] * w2) // div % 256 for i in range(32)]
                if 119 in pairs:
                    if check_key(pairs, f"lhiu_w{w1}{w2}_m{mult40}_{mult53}_div{div}"):
                        exit()

# ============================================================================
# Approach 3: 09111819 as direct byte values or positions
# ============================================================================
print("\n[3] Mini puzzle digits as direct values...")

# Interpret 09111819 as: byte positions 0,9,11,18,19 are special
special_positions = [0, 9, 11, 18, 19]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64]:
            base_pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Force 119 at special positions
            for pos in special_positions:
                if pos < 32:
                    test_pairs = base_pairs.copy()
                    test_pairs[pos] = 119
                    if check_key(test_pairs, f"force119_pos{pos}_m{mult40}_{mult53}_div{div}"):
                        exit()

# ============================================================================
# Approach 4: FIN as a split point - different operations before/after
# ============================================================================
print("\n[4] FIN as operation boundary...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Different interpretations of where FIN splits the 32 bytes
        for fin_pos in [8, 16, 24]:  # Position where operation changes
            for div1 in [32, 64]:
                for div2 in [32, 64, 128]:
                    pairs = []
                    for i in range(32):
                        if i < fin_pos:
                            val = (shell_m[i*2] + shell_m[i*2+1]) // div1 % 256
                        else:
                            val = (shell_m[i*2] + shell_m[i*2+1]) // div2 % 256
                        pairs.append(val)

                    if 119 in pairs:
                        if check_key(pairs, f"fin_split{fin_pos}_d{div1}_{div2}_m{mult40}_{mult53}"):
                            exit()

# ============================================================================
# Approach 5: Grid traversal based on sequences
# ============================================================================
print("\n[5] Grid traversal with sequence patterns...")

# Read rectangles in order dictated by mini puzzle
full_seq = seq1 + seq2  # [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for start in range(8):
            for div in [32, 64]:
                # Use sequence as step sizes through the grid
                idx = start
                visited = []
                for step in (full_seq * 4)[:64]:  # Enough to cover all
                    if len(visited) < 64:
                        visited.append(idx % 64)
                        idx = (idx + step) % 64

                if len(set(visited)) >= 32:
                    pairs = []
                    unique = []
                    for v in visited:
                        if v not in unique:
                            unique.append(v)

                    for i in range(32):
                        if i*2 < len(unique) and i*2+1 < len(unique):
                            idx1 = unique[i*2]
                            idx2 = unique[i*2+1]
                            val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                            pairs.append(val)

                    if len(pairs) == 32 and 119 in pairs:
                        if check_key(pairs, f"traverse_start{start}_m{mult40}_{mult53}_div{div}"):
                            exit()

# ============================================================================
# Approach 6: XOR with LHIU values
# ============================================================================
print("\n[6] XOR with LHIU constants...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64, 128]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR each byte with rotating LHIU
            lhiu = [L, H, I, U]
            pairs = [base[i] ^ lhiu[i % 4] for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"xor_lhiu_m{mult40}_{mult53}_div{div}"):
                    exit()

            # XOR with combined LHIU value
            combined = L ^ H ^ I ^ U
            pairs = [b ^ combined for b in base]
            if 119 in pairs:
                if check_key(pairs, f"xor_lhiu_comb_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 7: Using the exact numbers 09111819 and 11122111
# ============================================================================
print("\n[7] Direct number usage...")

num1 = 9111819
num2 = 11122111

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR with the numbers (mod 256)
            pairs = [base[i] ^ (num1 >> (8 * (i % 4))) % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"xor_num1_m{mult40}_{mult53}_div{div}"):
                    exit()

            # Use as seed for modification
            mod_val = (num1 + num2) % 256
            pairs = [(b + mod_val) % 256 for b in base]
            if 119 in pairs:
                if check_key(pairs, f"add_nums_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 8: Alternating between operations (seq1 vs seq2)
# ============================================================================
print("\n[8] Alternating operations based on sequences...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64]:
            pairs = []
            for i in range(32):
                s1 = seq1[i % 8]
                s2 = seq2[i % 8]

                # Use s1 and s2 to determine operation
                if s1 == 0:  # 0 might mean XOR
                    val = (shell_m[i*2] ^ shell_m[i*2+1]) % 256
                elif s1 == 1:  # 1 might mean add
                    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                elif s1 == 8:  # 8 might mean shift
                    val = ((shell_m[i*2] + shell_m[i*2+1]) >> 3) % 256
                elif s1 == 9:  # 9 might mean multiply factor
                    val = ((shell_m[i*2] + shell_m[i*2+1]) * 9) // (div * 9) % 256
                else:
                    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256

                # Apply s2 as modifier
                val = (val + s2) % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"alt_ops_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 9: Non-consecutive but structured pairing from mini puzzle
# ============================================================================
print("\n[9] Structured non-consecutive pairing...")

# "consecutive" is struck through - hint to NOT use consecutive pairing
# Maybe pair based on the mini puzzle digits?

# Interpret 09111819 11122111 as pairing instructions
# Pair rect 0 with rect 9, rect 1 with rect 1 (itself? or +1?), etc.

for interpretation in range(3):
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            for div in [32, 64]:
                pairs = []
                digits = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

                for i in range(32):
                    if interpretation == 0:
                        # Digit as offset from position
                        idx1 = i * 2
                        idx2 = (i * 2 + digits[i % 16]) % 64
                    elif interpretation == 1:
                        # Digits define both indices
                        idx1 = digits[i % 16]
                        idx2 = digits[(i + 8) % 16]
                    else:
                        # Digit as skip pattern
                        idx1 = i * 2
                        idx2 = (idx1 + 1 + digits[i % 16]) % 64

                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                if 119 in pairs:
                    if check_key(pairs, f"struct_pair_int{interpretation}_m{mult40}_{mult53}_div{div}"):
                        exit()

# ============================================================================
# Approach 10: The /x? could mean divide by unknown
# ============================================================================
print("\n[10] Variable divisor per position...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Use seq1 and seq2 as divisor modifiers
        for base_div in [8, 16, 32]:
            pairs = []
            for i in range(32):
                div_mod = seq1[i % 8] + seq2[i % 8]
                if div_mod == 0:
                    div_mod = 1
                actual_div = base_div * div_mod
                val = (shell_m[i*2] + shell_m[i*2+1]) // actual_div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"var_div_m{mult40}_{mult53}_base{base_div}"):
                    exit()

# ============================================================================
# Approach 11: Three-rectangle combinations (not pairs)
# ============================================================================
print("\n[11] Three-rectangle combinations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [64, 128, 256]:
            # Use 3 consecutive rects, skip every other for 32 bytes
            pairs = [(shell_m[i*2] + shell_m[i*2+1] + shell_m[(i*2+2) % 64]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"three_rect_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 12: Maybe the strikethrough means subtraction
# ============================================================================
print("\n[12] Subtraction instead of addition...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [1, 8, 16, 32]:
            # Absolute difference
            pairs = [abs(shell_m[i*2] - shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"subtract_abs_m{mult40}_{mult53}_div{div}"):
                    exit()

            # Signed difference (wrap around)
            pairs = [(shell_m[i*2] - shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"subtract_m{mult40}_{mult53}_div{div}"):
                    exit()

print("\nTargeted search complete.")
print("No solution found with these approaches.")
