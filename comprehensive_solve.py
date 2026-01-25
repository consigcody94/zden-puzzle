"""
Comprehensive solver trying all area types with divisors 7, 64, 127
Including Outer and Inner areas, not just Shell
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
print("COMPREHENSIVE SOLVER")
print("="*70)

tested = 0

# All area types
area_types = {
    'shell': shell,
    'outer': outer,
    'inner': inner
}

# Key divisors
divisors = [7, 64, 127, 17, 119]

# Multipliers for special rectangles
mult40_options = [1, 7, 17]
mult53_options = [1, 6, 7]

# ============================================================================
# Test all combinations of area type, divisor, multipliers
# ============================================================================
print("\n[1] Systematic search across area types and divisors...")

for area_name, areas in area_types.items():
    for div in divisors:
        for mult40 in mult40_options:
            for mult53 in mult53_options:
                areas_m = areas.copy()
                areas_m[39] *= mult40
                areas_m[52] *= mult53

                # Basic sum / div
                pairs = [(areas_m[i*2] + areas_m[i*2+1]) // div % 256 for i in range(32)]
                tested += 1
                if 119 in pairs:
                    if check_key(pairs, f"{area_name}_div{div}_m{mult40}_{mult53}"):
                        exit()

                # Difference / div
                pairs = [abs(areas_m[i*2] - areas_m[i*2+1]) // div % 256 for i in range(32)]
                tested += 1
                if check_key(pairs, f"{area_name}_diff_div{div}_m{mult40}_{mult53}"):
                    exit()

                # XOR / div
                pairs = [(areas_m[i*2] ^ areas_m[i*2+1]) // div % 256 for i in range(32)]
                tested += 1
                if check_key(pairs, f"{area_name}_xor_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Mix of area types (e.g., Outer + Inner)
# ============================================================================
print("\n[2] Mixed area operations...")

for div in divisors:
    for mult40 in mult40_options:
        for mult53 in mult53_options:
            outer_m = outer.copy()
            inner_m = inner.copy()
            shell_m = shell.copy()
            outer_m[39] *= mult40
            outer_m[52] *= mult53
            inner_m[39] *= mult40
            inner_m[52] *= mult53
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            # Outer + Inner
            pairs = [(outer_m[i*2] + inner_m[i*2+1]) // div % 256 for i in range(32)]
            tested += 1
            if check_key(pairs, f"outer_plus_inner_div{div}_m{mult40}_{mult53}"):
                exit()

            # Outer - Inner (= Shell, but computed differently with multipliers)
            pairs = [(outer_m[i*2] - inner_m[i*2] + outer_m[i*2+1] - inner_m[i*2+1]) // div % 256 for i in range(32)]
            tested += 1
            if check_key(pairs, f"outer_minus_inner_div{div}_m{mult40}_{mult53}"):
                exit()

            # (Outer * Shell) / div
            pairs = [(outer_m[i*2] * shell_m[i*2+1]) // (div * 1000) % 256 for i in range(32)]
            tested += 1
            if check_key(pairs, f"outer_times_shell_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Non-consecutive pairing with divisors 7, 64, 127
# ============================================================================
print("\n[3] Non-consecutive pairing patterns...")

# Skip patterns
for skip in [1, 2, 3, 4, 8, 16, 32]:
    for div in [7, 64, 127]:
        for mult40 in [1, 17]:
            for mult53 in [1, 6]:
                shell_m = shell.copy()
                shell_m[39] *= mult40
                shell_m[52] *= mult53

                pairs = []
                for i in range(32):
                    idx1 = i
                    idx2 = (i + skip) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                tested += 1
                if 119 in pairs:
                    if check_key(pairs, f"skip{skip}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Column-major and diagonal patterns
# ============================================================================
print("\n[4] Grid-based patterns...")

# Column-major ordering
col_order = []
for col in range(8):
    for row in range(8):
        col_order.append(row * 8 + col)

for div in [7, 64, 127]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            pairs = [(shell_m[col_order[i*2]] + shell_m[col_order[i*2+1]]) // div % 256 for i in range(32)]
            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"col_major_div{div}_m{mult40}_{mult53}"):
                    exit()

# Diagonal
for diag_offset in [1, 7, 9]:
    for div in [7, 64, 127]:
        for mult40 in [1, 17]:
            for mult53 in [1, 6]:
                shell_m = shell.copy()
                shell_m[39] *= mult40
                shell_m[52] *= mult53

                pairs = []
                for i in range(32):
                    idx1 = i
                    idx2 = (i + diag_offset) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                tested += 1
                if 119 in pairs:
                    if check_key(pairs, f"diag{diag_offset}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Using the sequence as pair indices
# ============================================================================
print("\n[5] Sequence-guided pairing...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
full_seq = seq1 + seq2

for div in [7, 64, 127]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            # Use sequence as offset for second element
            pairs = []
            for i in range(32):
                offset = full_seq[i % 16]
                idx1 = i * 2
                idx2 = (i * 2 + 1 + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"seq_offset_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Use sequence as step through the grid
            pairs = []
            idx = 0
            for i in range(32):
                step = full_seq[i % 16]
                if step == 0:
                    step = 1
                idx1 = idx % 64
                idx2 = (idx + step) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)
                idx = (idx + step * 2) % 64

            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"seq_step_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Reverse byte order
# ============================================================================
print("\n[6] Reverse orderings...")

for div in [7, 64, 127]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            # Reverse rectangle order
            shell_r = shell_m[::-1]
            pairs = [(shell_r[i*2] + shell_r[i*2+1]) // div % 256 for i in range(32)]
            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"reverse_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Reverse byte order in result
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
            pairs = pairs[::-1]
            tested += 1
            if check_key(pairs, f"result_reverse_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Single byte per rectangle (64 -> 32 by some method)
# ============================================================================
print("\n[7] Single byte per rectangle methods...")

for div in [7, 64, 127, 16, 32]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            # First 32 rects
            pairs = [shell_m[i] // div % 256 for i in range(32)]
            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"first32_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Every other rect
            pairs = [shell_m[i*2] // div % 256 for i in range(32)]
            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"evens_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Odd rects
            pairs = [shell_m[i*2+1] // div % 256 for i in range(32)]
            tested += 1
            if 119 in pairs:
                if check_key(pairs, f"odds_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Bitwise operations
# ============================================================================
print("\n[8] Bitwise operations...")

for div in [7, 64, 127]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            # AND operation
            pairs = [(shell_m[i*2] & shell_m[i*2+1]) // div % 256 for i in range(32)]
            tested += 1
            if check_key(pairs, f"and_div{div}_m{mult40}_{mult53}"):
                exit()

            # OR operation
            pairs = [(shell_m[i*2] | shell_m[i*2+1]) // div % 256 for i in range(32)]
            tested += 1
            if check_key(pairs, f"or_div{div}_m{mult40}_{mult53}"):
                exit()

print(f"\nTested {tested} combinations.")
print("Comprehensive search complete.")
