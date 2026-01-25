"""
The hint says "consecutive" is struck through, meaning NOT consecutive.
09111819 could be the OFFSET pattern for pairing.

For each byte position, instead of pairing rect[2i] with rect[2i+1],
we pair rect[2i] with rect[2i + offset[i]]
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
print("OFFSET-BASED PAIRING (NOT CONSECUTIVE)")
print("="*70)

# The sequence 09111819 could be interpreted multiple ways
seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
full_seq = seq1 + seq2

# Alternative reading: 09-11-18-19 as two-digit numbers
two_digit = [9, 11, 18, 19, 11, 12, 21, 11]  # Rough interpretation

# ============================================================================
# Test 1: Use seq1 as offset for first half, seq2 for second half
# ============================================================================
print("\n[1] Sequence as pairing offsets...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Offset interpretation 1:
            # rect[i] pairs with rect[i + offset]
            pairs = []
            for i in range(32):
                offset = full_seq[i % 16]
                if offset == 0:
                    offset = 1  # Can't pair with self
                idx1 = i
                idx2 = (i + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                print(f"  Offset v1 div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"offset_v1_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Offset interpretation 2:
            # Standard pair base, but offset the second element
            pairs = []
            for i in range(32):
                offset = full_seq[i % 16]
                idx1 = i * 2
                idx2 = (i * 2 + 1 + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                print(f"  Offset v2 div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"offset_v2_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 2: Different offset interpretations
# ============================================================================
print("\n[2] Alternative offset patterns...")

# Maybe 0,9,1,1,1,8,1,9 means:
# Skip 0, skip 9, skip 1, skip 1, skip 1, skip 8, skip 1, skip 9 for consecutive pairs

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Build pairs by skipping according to sequence
            pairs = []
            idx = 0
            for i in range(32):
                offset = full_seq[i % 16]
                if offset == 0:
                    offset = 1
                idx1 = idx % 64
                idx2 = (idx + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)
                idx = (idx2 + 1) % 64

            if 119 in pairs:
                print(f"  Skip pattern div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"skip_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 3: Grid-based interpretation
# ============================================================================
print("\n[3] Grid-based offset (row/column moves)...")

# 8x8 grid, sequence might indicate row/column offsets
# 0 = same cell, 9 = next row + 1 col, 1 = next col, 8 = next row, etc.

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Interpret offset as grid moves
            pairs = []
            for i in range(32):
                row1 = (i * 2) // 8
                col1 = (i * 2) % 8

                offset = full_seq[i % 16]
                # Move by offset in reading order
                idx2 = ((i * 2) + offset + 1) % 64

                idx1 = i * 2
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                print(f"  Grid offset div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"grid_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: "Following" could mean the rectangle that comes after in some order
# ============================================================================
print("\n[4] 'Following' as next in various orderings...")

# Column-major order
col_order = []
for col in range(8):
    for row in range(8):
        col_order.append(row * 8 + col)

# Spiral order (simplified)
spiral_order = list(range(64))  # Would need to compute actual spiral

# Zigzag order
zigzag_order = []
for row in range(8):
    if row % 2 == 0:
        zigzag_order.extend(range(row * 8, (row + 1) * 8))
    else:
        zigzag_order.extend(range((row + 1) * 8 - 1, row * 8 - 1, -1))

for order_name, order in [('col_major', col_order), ('zigzag', zigzag_order)]:
    for mult40 in [1, 17]:
        for mult53 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult40
            shell_m[52] *= mult53

            for div in [7, 64, 127]:
                # Pair element i with element i+offset in the ordering
                pairs = []
                for i in range(32):
                    offset = full_seq[i % 16]
                    if offset == 0:
                        offset = 1
                    pos1 = i
                    pos2 = (i + offset) % 64
                    idx1 = order[pos1]
                    idx2 = order[pos2]
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                if 119 in pairs:
                    print(f"  {order_name} div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                    if check_key(pairs, f"{order_name}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 5: Maybe sequence defines which TWO rectangles to sum for each byte
# ============================================================================
print("\n[5] Sequence as rectangle indices...")

# 09111819 could mean: byte 0 uses rects 0 and 9, byte 1 uses rects 1 and 1, etc.
# But that doesn't give us 32 bytes from 8 digits...

# Maybe repeat: byte 0: rects 0,9; byte 1: rects 1,1; byte 2: rects 1,1; ... (cycling)

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                # Use pairs of sequence values
                s_idx = (i * 2) % 16
                idx1 = full_seq[s_idx]
                idx2 = full_seq[(s_idx + 1) % 16]
                # Scale up to use more rectangles
                idx1 = (idx1 * 4 + i) % 64
                idx2 = (idx2 * 4 + i) % 64
                if idx1 == idx2:
                    idx2 = (idx2 + 1) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                print(f"  Seq indices div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"seq_idx_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 6: Maybe 09-11-18-19 are byte POSITIONS, and 11-12-21-11 are values/ops
# ============================================================================
print("\n[6] Position-based interpretation...")

# Positions: 9, 11, 18, 19 (or 0, 9, 11, 18, 19)
positions = [0, 9, 11, 18, 19]
after_fix_positions = [11, 12, 21]  # 11-12-21-11 interpreted as positions

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Maybe these positions get special values or operations
            pairs = base.copy()
            for pos in positions:
                if pos < 32:
                    pairs[pos] = 119  # Force 0x77

            if check_key(pairs, f"force_pos_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 7: XOR between sequence and computed values
# ============================================================================
print("\n[7] XOR with sequence values...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR each byte with corresponding sequence value
            pairs = [base[i] ^ full_seq[i % 16] for i in range(32)]
            if 119 in pairs:
                print(f"  XOR seq div{div} m{mult40}_{mult53}: 119 at {[i for i,v in enumerate(pairs) if v==119]}")
                if check_key(pairs, f"xor_seq_div{div}_m{mult40}_{mult53}"):
                    exit()

            # XOR with larger sequence value (scaled)
            pairs = [base[i] ^ (full_seq[i % 16] * 10) % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"xor_seq10_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 8: Combine all insights - div 7 gives 119 at pos 19 with m17
# ============================================================================
print("\n[8] Building on known: div7 + m17 gives 119 at pos 19...")

shell_m = shell.copy()
shell_m[39] *= 17
shell_m[52] *= 6

# We know: pairs[19] = 119 with div 7
base_div7 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]
print(f"Base div7: {base_div7}")
print(f"Position 19 = {base_div7[19]}")

# What if we need to apply the sequence to modify other bytes?
# Try adding sequence values to shift bytes
for shift in [0, 50, 100, 119]:
    pairs = [(base_div7[i] + shift) % 256 for i in range(32)]
    if check_key(pairs, f"div7_shift{shift}"):
        exit()

# Try different operations on the base
for xor_val in [0, 64, 119, 127]:
    pairs = [base_div7[i] ^ xor_val for i in range(32)]
    if check_key(pairs, f"div7_xor{xor_val}"):
        exit()

print("\nOffset pairing search complete.")
