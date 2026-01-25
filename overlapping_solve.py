"""
OVERLAPPING PAIRS interpretation!
Instead of: [0+1], [2+3], [4+5]... (non-overlapping)
Try: [0+1], [1+2], [2+3]... (overlapping/sliding window)

This would give us 63 possible pairs from 64 rectangles.
We need to select 32 of them for the private key.
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
print("OVERLAPPING PAIRS SOLVER")
print("="*70)
print("Trying: [0+1], [1+2], [2+3]... instead of [0+1], [2+3], [4+5]...")
print()

# ============================================================================
# Test 1: Sliding window, take every other pair
# ============================================================================
print("[1] Sliding window, every other pair...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Compute all 63 overlapping sums
        overlapping = [shell_m[i] + shell_m[i+1] for i in range(63)]

        for div in [7, 64, 127]:
            # Take every other overlapping pair (0, 2, 4, ...)
            pairs = [overlapping[i*2] // div % 256 for i in range(32) if i*2 < 63]
            if len(pairs) == 32 and 119 in pairs:
                if check_key(pairs, f"overlap_even_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Take odd overlapping pairs (1, 3, 5, ...)
            pairs = [overlapping[i*2+1] // div % 256 for i in range(31)]
            pairs.append(overlapping[0] // div % 256)  # Wrap around
            if len(pairs) == 32 and 119 in pairs:
                if check_key(pairs, f"overlap_odd_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 2: First 32 overlapping pairs
# ============================================================================
print("\n[2] First 32 overlapping pairs directly...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        overlapping = [shell_m[i] + shell_m[i+1] for i in range(63)]

        for div in [7, 64, 127]:
            pairs = [overlapping[i] // div % 256 for i in range(32)]
            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"first32_overlap_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 3: Last 32 overlapping pairs
# ============================================================================
print("\n[3] Last 32 overlapping pairs...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        overlapping = [shell_m[i] + shell_m[i+1] for i in range(63)]

        for div in [7, 64, 127]:
            pairs = [overlapping[31+i] // div % 256 for i in range(32)]
            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"last32_overlap_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: Middle 32 overlapping pairs
# ============================================================================
print("\n[4] Middle 32 overlapping pairs (15-46)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        overlapping = [shell_m[i] + shell_m[i+1] for i in range(63)]

        for div in [7, 64, 127]:
            for start in range(32):  # Try different starting positions
                pairs = [overlapping[(start+i) % 63] // div % 256 for i in range(32)]
                if 119 in pairs:
                    if check_key(pairs, f"mid_start{start}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 5: Overlapping with skip from mini-puzzle
# ============================================================================
print("\n[5] Overlapping pairs with skip pattern...")

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
full_seq = (seq1 + seq2) * 2

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                skip = full_seq[i]
                idx = (i * 2 + skip) % 63
                val = (shell_m[idx] + shell_m[idx + 1]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"overlap_skip_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 6: Row-wise overlapping in 8x8 grid
# ============================================================================
print("\n[6] Row-wise overlapping pairs...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Each row of 8: compute 7 overlapping pairs, use 4 per row = 32 total
            pairs = []
            for row in range(8):
                row_start = row * 8
                for col in range(4):  # 4 pairs per row
                    idx = row_start + col * 2
                    if idx + 1 < 64:
                        val = (shell_m[idx] + shell_m[idx + 1]) // div % 256
                        pairs.append(val)

            if len(pairs) == 32 and 119 in pairs:
                if check_key(pairs, f"row_overlap_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 7: Column-wise overlapping in 8x8 grid
# ============================================================================
print("\n[7] Column-wise overlapping pairs...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for col in range(8):
                for row in range(4):  # 4 pairs per column
                    idx1 = row * 16 + col
                    idx2 = row * 16 + col + 8
                    if idx2 < 64:
                        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                        pairs.append(val)

            if len(pairs) == 32 and 119 in pairs:
                if check_key(pairs, f"col_overlap_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 8: Diagonal overlapping
# ============================================================================
print("\n[8] Diagonal overlapping pairs...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                idx1 = i
                idx2 = i + 9  # Diagonal in 8x8 grid (row+1, col+1)
                if idx2 < 64:
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)
                else:
                    val = (shell_m[idx1] + shell_m[idx2 % 64]) // div % 256
                    pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"diag_overlap_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 9: "Following" could mean next row (skip 8)
# ============================================================================
print("\n[9] Following = next row (skip 8)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                idx1 = i
                idx2 = (i + 8) % 64  # Next row
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  skip8 div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"skip8_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 10: Pair position i with position 63-i (mirror)
# ============================================================================
print("\n[10] Mirror pairing (i with 63-i)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                idx1 = i
                idx2 = 63 - i
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  mirror div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"mirror_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 11: XOR pairs instead of sum
# ============================================================================
print("\n[11] XOR instead of sum...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [1, 7, 64, 127]:
            pairs = []
            for i in range(32):
                xored = shell_m[i * 2] ^ shell_m[i * 2 + 1]
                val = xored // max(div, 1) % 256
                pairs.append(val)

            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  xor div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"xor_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 12: Subtract pairs instead of sum (lightning above = add, skull below = subtract?)
# ============================================================================
print("\n[12] Subtract pairs (skull operation)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                diff = abs(shell_m[i * 2] - shell_m[i * 2 + 1])
                val = diff // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"subtract_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 13: Multiply pairs
# ============================================================================
print("\n[13] Multiply pairs...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [10000, 100000, 1000000]:
            pairs = []
            for i in range(32):
                prod = shell_m[i * 2] * shell_m[i * 2 + 1]
                val = prod // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"multiply_div{div}_m{mult40}_{mult53}"):
                    exit()

print("\nOverlapping pairs search complete.")
