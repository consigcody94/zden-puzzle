"""
NEW INTERPRETATION:
09111819 FIX 11122111 defines the OFFSET pattern for pairing

Each digit tells us the offset to add to find the "following" rectangle:
- Digit 0: pair rect[i*2] with rect[i*2 + 0]
- Digit 9: pair rect[i*2] with rect[i*2 + 9]
- etc.

Or maybe: the sequence defines row/column traversal in the 8x8 grid
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
print("OFFSET PATTERN FROM MINI-PUZZLE")
print("="*70)

# Mini-puzzle digits
seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # 09111819 (before FIX)
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # 11122111 (after FIX)

# ============================================================================
# Test 1: Each digit is an offset for that byte position
# ============================================================================
print("[1] Digits as offsets for each byte position...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Full offset pattern (repeat seq1 and seq2)
            full_offsets = (seq1 * 2) + (seq2 * 2)  # 32 offsets for 32 bytes

            pairs = []
            for i in range(32):
                offset = full_offsets[i]
                idx1 = i * 2
                idx2 = (i * 2 + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  div{div} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"offset_pattern_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 2: Offset is fixed for each half (seq1 vs seq2)
# ============================================================================
print("\n[2] Fixed offset per half (average of seq1/seq2)...")

# Average offset from seq1 = (0+9+1+1+1+8+1+9)/8 = 3.75 ~ 4
# Average offset from seq2 = (1+1+1+2+2+1+1+1)/8 = 1.25 ~ 1

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            for off1 in [1, 4, 9]:
                for off2 in [1, 2]:
                    pairs = []
                    for i in range(32):
                        if i < 16:
                            offset = off1
                        else:
                            offset = off2

                        idx1 = i * 2
                        idx2 = (i * 2 + offset) % 64
                        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                        pairs.append(val)

                    if 119 in pairs:
                        if check_key(pairs, f"fixed_off{off1}_{off2}_div{div}_m{mult40}_{mult53}"):
                            exit()

# ============================================================================
# Test 3: 09111819 and 11122111 as two-digit hex values
# ============================================================================
print("\n[3] Sequences as hex values to XOR...")

# 0x09111819 = 152,114,201
# 0x11122111 = 286,400,785

hex1 = 0x09111819
hex2 = 0x11122111

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR first 16 with hex1, last 16 with hex2
            pairs = []
            for i in range(16):
                xor_byte = (hex1 >> (8 * (3 - (i % 4)))) & 0xFF
                pairs.append(base[i] ^ xor_byte)
            for i in range(16, 32):
                xor_byte = (hex2 >> (8 * (3 - ((i-16) % 4)))) & 0xFF
                pairs.append(base[i] ^ xor_byte)

            if 119 in pairs:
                if check_key(pairs, f"hex_xor_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: Maybe the sequences define START positions, not offsets
# ============================================================================
print("\n[4] Sequences as start positions in 8x8 grid...")

# 8x8 grid: position (r,c) = r*8 + c
# 09111819 could mean: row 0 col 9 (invalid), or positions 9, 11, 18, 19...

start_positions = [9, 11, 18, 19, 11, 12, 21, 11]  # Two-digit interpretations

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Build pairs starting from each position
            for start_offset in [0, 1]:
                pairs = []
                for i in range(32):
                    start = start_positions[i % 8] + start_offset
                    idx1 = start % 64
                    idx2 = (start + 1) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                if 119 in pairs:
                    if check_key(pairs, f"start_pos_off{start_offset}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 5: FIX means swap/exchange between the two sequences
# ============================================================================
print("\n[5] FIX as swap operation between sequences...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Swap positions indicated by sequences
            pairs = base.copy()

            # seq1 positions: 0, 9, 11, 18, 19 (where digit changes)
            # seq2 positions: 11, 12, 21 (where digit changes)
            swap_pairs = [(0, 9), (9, 11), (11, 18), (18, 19), (19, 11), (11, 12), (12, 21), (21, 11)]

            for p1, p2 in swap_pairs:
                if p1 < 32 and p2 < 32:
                    pairs[p1], pairs[p2] = pairs[p2], pairs[p1]

            if check_key(pairs, f"swap_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 6: Reading pattern from the grid
# Row 0: read at columns defined by seq1
# Row 1: read at columns defined by seq2
# etc.
# ============================================================================
print("\n[6] Grid reading pattern from sequences...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Try reading grid in pattern defined by sequences
            pairs = []

            # Each row of 8 uses one of the sequences
            for row in range(4):  # 4 rows of pairs
                for col_idx in range(8):
                    if row % 2 == 0:
                        offset = seq1[col_idx]
                    else:
                        offset = seq2[col_idx]

                    idx = row * 16 + col_idx * 2
                    idx2 = (idx + offset) % 64
                    val = (shell_m[idx] + shell_m[idx2]) // div % 256
                    pairs.append(val)

            if len(pairs) == 32 and 119 in pairs:
                if check_key(pairs, f"grid_read_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 7: The numbers 09, 11, 18, 19 and 11, 12, 21, 11 are byte VALUES
# ============================================================================
print("\n[7] Sequences as actual byte values...")

# The mini-puzzle might be telling us specific byte values:
# Bytes from seq: 0x09, 0x11, 0x18, 0x19, 0x11, 0x12, 0x21, 0x11
byte_values = [0x09, 0x11, 0x18, 0x19, 0x11, 0x12, 0x21, 0x11]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Prepend the byte values
            pairs = byte_values + base[:24]
            if 0x77 in pairs or check_key(pairs, f"prepend_bytes_div{div}_m{mult40}_{mult53}"):
                exit()

            # Insert at specific positions
            pairs = base.copy()
            for i, bv in enumerate(byte_values):
                if i < 32:
                    pairs[i] = bv

            if check_key(pairs, f"replace_bytes_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 8: What if we need to generate bytes 0-7 from seq1, 8-15 from seq2?
# ============================================================================
print("\n[8] First 8 bytes use seq1 offsets, next 8 use seq2...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []

            # First 8 bytes: use seq1 offsets
            for i in range(8):
                offset = seq1[i]
                idx1 = i * 2
                idx2 = (i * 2 + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            # Next 8 bytes: use seq2 offsets
            for i in range(8):
                offset = seq2[i]
                idx1 = 16 + i * 2
                idx2 = (16 + i * 2 + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            # Remaining 16 bytes: standard consecutive
            for i in range(16, 32):
                idx1 = i * 2
                idx2 = i * 2 + 1
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"split_seq_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 9: Lightning = power, Skull = modulo (death = remainder)
# ============================================================================
print("\n[9] Lightning as power, Skull as modulo...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for power in [2, 3]:
            for mod in [119, 127, 256]:
                pairs = []
                for i in range(32):
                    val = pow(shell_m[i * 2] + shell_m[i * 2 + 1], power) % mod
                    pairs.append(val % 256)

                if 119 in pairs:
                    if check_key(pairs, f"pow{power}_mod{mod}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 10: Using outer areas with the mini-puzzle pattern
# ============================================================================
print("\n[10] Outer areas with offset pattern...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer_m = outer.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53

        full_offsets = (seq1 * 2) + (seq2 * 2)

        for div in [64, 128, 256]:
            pairs = []
            for i in range(32):
                offset = full_offsets[i]
                idx1 = i * 2
                idx2 = (i * 2 + offset) % 64
                val = (outer_m[idx1] + outer_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"outer_offset_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 11: Combine formula interpretation with offset pattern
# Formula: -I *X+ LXIV /x/ = (-Inner * 10 + 64) / x
# ============================================================================
print("\n[11] Formula with offset pattern...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        inner_m = inner.copy()
        shell_m = shell.copy()
        inner_m[39] *= mult40
        inner_m[52] *= mult53
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        full_offsets = (seq1 * 2) + (seq2 * 2)

        for x in [7, 10, 64]:
            pairs = []
            for i in range(32):
                offset = full_offsets[i]
                idx1 = i * 2
                idx2 = (i * 2 + offset) % 64

                # Apply formula: (-I * 10 + 64) / x
                I = inner_m[idx1] + inner_m[idx2]
                result = abs((-I * 10 + 64) // x) % 256
                pairs.append(result)

            if 119 in pairs:
                if check_key(pairs, f"formula_offset_x{x}_m{mult40}_{mult53}"):
                    exit()

            # Try with Shell instead
            pairs = []
            for i in range(32):
                offset = full_offsets[i]
                idx1 = i * 2
                idx2 = (i * 2 + offset) % 64

                S = shell_m[idx1] + shell_m[idx2]
                result = (S * 10 + 64) // max(x, 1) % 256
                pairs.append(result)

            if 119 in pairs:
                if check_key(pairs, f"formula_shell_x{x}_m{mult40}_{mult53}"):
                    exit()

print("\nOffset pattern search complete.")
print("\n" + "="*70)
print("SUMMARY OF KEY FINDINGS:")
print("="*70)
print("1. With mult17 at rect 39 and div7, byte[19] = 119 (0x77)")
print("2. 839 (shell[39]) * 17 / 7 relates to 119")
print("3. 'Consecutive' was crossed out - pairing is NOT [0+1, 2+3, ...]")
print("4. Mini-puzzle 09111819 FIX 11122111 likely defines the pattern")
print("5. Lightning (XOR?) above FIX, Skull (subtract?) below FIX")
print("6. LXIV = 64 is prominently featured")
