"""
Deep analysis of mini-puzzle: 09111819 FIX 11122111

Let's decode this systematically:
1. As coordinates in 8x8 grid
2. As binary/hex values
3. As instructions
4. As row/column indices
5. As mathematical operations
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
print("MINI-PUZZLE DEEP ANALYSIS")
print("="*70)

# The sequences
seq_before = "09111819"  # Before FIX
seq_after = "11122111"   # After FIX

print(f"Before FIX: {seq_before}")
print(f"After FIX: {seq_after}")
print()

# ============================================================================
# Analysis 1: As pairs of digits (row, col) or (index, offset)
# ============================================================================
print("=== INTERPRETATION 1: As digit pairs ===")
print("09111819 -> (0,9) (1,1) (1,8) (1,9)")
print("11122111 -> (1,1) (1,2) (2,1) (1,1)")
print()

# But columns only go 0-7 in 8x8, so 9 is invalid...
# Unless it wraps: 9 % 8 = 1

pairs_before = [(0, 9 % 8), (1, 1), (1, 8 % 8), (1, 9 % 8)]  # = [(0,1), (1,1), (1,0), (1,1)]
pairs_after = [(1, 1), (1, 2), (2, 1), (1, 1)]

print("With modulo 8:")
print(f"  Before: {pairs_before}")
print(f"  After: {pairs_after}")

# ============================================================================
# Analysis 2: As rectangle indices
# ============================================================================
print("\n=== INTERPRETATION 2: As 2-digit rectangle indices ===")
indices_before = [9, 11, 18, 19]  # From 09, 11, 18, 19
indices_after = [11, 12, 21, 11]  # From 11, 12, 21, 11

print(f"  Before FIX indices: {indices_before}")
print(f"  After FIX indices: {indices_after}")

# Shell values at these indices
print(f"  Shell at before indices: {[shell[i] for i in indices_before]}")
print(f"  Shell at after indices: {[shell[i] for i in indices_after]}")

# ============================================================================
# Analysis 3: Sum = constant?
# ============================================================================
print("\n=== INTERPRETATION 3: Digit sums ===")
sum_before = sum(int(d) for d in seq_before)
sum_after = sum(int(d) for d in seq_after)
print(f"  Sum of digits before FIX: {sum_before}")
print(f"  Sum of digits after FIX: {sum_after}")
print(f"  Total: {sum_before + sum_after}")

# ============================================================================
# Analysis 4: As binary patterns
# ============================================================================
print("\n=== INTERPRETATION 4: As binary ===")
bin_before = int(seq_before, 10)  # 9111819 as decimal
bin_after = int(seq_after, 10)    # 11122111 as decimal

print(f"  {seq_before} decimal = {bin_before}")
print(f"  {seq_after} decimal = {bin_after}")
print(f"  {seq_before} binary = {bin(bin_before)}")
print(f"  {seq_after} binary = {bin(bin_after)}")

# ============================================================================
# Analysis 5: Pattern observation
# ============================================================================
print("\n=== INTERPRETATION 5: Pattern analysis ===")
print("Before: 0-9-1-1-1-8-1-9")
print("After:  1-1-1-2-2-1-1-1")
print()
print("Observations:")
print("- Before has 0, 9, 8 (larger digits)")
print("- After only has 1 and 2 (small digits)")
print("- Both have four 1s")
print("- 'FIX' might mean convert large digits to small?")

# ============================================================================
# Test: Use indices 9, 11, 18, 19 specially
# ============================================================================
print("\n[1] Special handling for rect indices 9, 11, 18, 19...")

special_indices = indices_before + indices_after  # [9, 11, 18, 19, 11, 12, 21, 11]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                # Use special indices if available
                if i < len(special_indices):
                    idx1 = special_indices[i]
                    idx2 = special_indices[(i + 1) % len(special_indices)]
                else:
                    idx1 = i * 2
                    idx2 = i * 2 + 1

                val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"special_idx_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 2: Maybe the sequences define which BYTES get which rectangles
# ============================================================================
print("\n[2] Sequences define byte-to-rectangle mapping...")

# Map bytes 0-7 to rectangles based on seq_before digits
# Map bytes 8-15 to rectangles based on seq_after digits

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []

            # First 8 bytes: use before sequence
            for i in range(8):
                digit = int(seq_before[i])
                idx1 = i * 2 + digit
                idx2 = i * 2 + digit + 1
                val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                pairs.append(val)

            # Next 8 bytes: use after sequence
            for i in range(8):
                digit = int(seq_after[i])
                idx1 = 16 + i * 2 + digit
                idx2 = 16 + i * 2 + digit + 1
                val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                pairs.append(val)

            # Remaining 16 bytes: standard
            for i in range(16, 32):
                idx1 = i * 2
                idx2 = i * 2 + 1
                val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"byte_map_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 3: 09111819 could mean "at position 0, skip 9; at position 1, skip 1; etc."
# ============================================================================
print("\n[3] Position-specific skip pattern...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []

            for i in range(32):
                if i < 8:
                    skip = int(seq_before[i])
                elif i < 16:
                    skip = int(seq_after[i - 8])
                else:
                    skip = 1  # Default skip

                idx1 = i * 2
                idx2 = (idx1 + skip) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"pos_skip_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: The numbers might indicate XOR mask pattern
# ============================================================================
print("\n[4] Sequences as XOR mask pattern...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR with digit pattern
            pairs = []
            for i in range(32):
                if i < 8:
                    xor_val = int(seq_before[i])
                elif i < 16:
                    xor_val = int(seq_after[i - 8])
                else:
                    xor_val = 0

                pairs.append(base[i] ^ xor_val)

            if 119 in pairs:
                if check_key(pairs, f"xor_pattern_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 5: 09111819 and 11122111 XORed together = pattern
# ============================================================================
print("\n[5] XOR of sequences defines transformation...")

xor_pattern = [int(seq_before[i]) ^ int(seq_after[i]) for i in range(8)]
print(f"  XOR pattern: {xor_pattern}")  # Should be: [1, 0, 0, 0, 1, 1, 0, 0]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Apply XOR pattern
            pairs = []
            for i in range(32):
                pattern_bit = xor_pattern[i % 8]
                if pattern_bit:
                    pairs.append(base[i] ^ 0x77)  # XOR with 119
                else:
                    pairs.append(base[i])

            if 0x77 in pairs:
                if check_key(pairs, f"xor_seq_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 6: "FIX" means set those positions to fixed value (119)
# ============================================================================
print("\n[6] FIX = set certain positions to 119...")

# Which positions? The digits themselves might indicate
# Before: 0,9,1,1,1,8,1,9 -> positions 0, 9 (where digit != 1)
# After: 1,1,1,2,2,1,1,1 -> positions 11, 12 (in second byte, where digit != 1)

fix_positions_before = [i for i, d in enumerate(seq_before) if d != '1']  # 0, 1, 5
fix_positions_after = [8 + i for i, d in enumerate(seq_after) if d != '1']  # 11, 12

print(f"  Fix positions (!=1 in before): {fix_positions_before}")
print(f"  Fix positions (!=1 in after): {fix_positions_after}")

all_fix = fix_positions_before + fix_positions_after

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            pairs = base.copy()
            for pos in all_fix:
                if pos < 32:
                    pairs[pos] = 119

            if check_key(pairs, f"fix_pos_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 7: Digit sum = row offset
# ============================================================================
print("\n[7] Digit sums as row offsets...")

# Sum of before = 30, sum of after = 10
# 30/8 = 3.75 -> row 3 or 4
# 10/8 = 1.25 -> row 1

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            for row_off_before in [3, 4, sum_before // 8]:
                for row_off_after in [1, 2, sum_after // 8]:
                    pairs = []

                    for i in range(16):
                        base_idx = i * 2
                        idx1 = base_idx + row_off_before * 8
                        idx2 = base_idx + row_off_before * 8 + 1
                        val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                        pairs.append(val)

                    for i in range(16):
                        base_idx = i * 2
                        idx1 = base_idx + row_off_after * 8
                        idx2 = base_idx + row_off_after * 8 + 1
                        val = (shell_m[idx1 % 64] + shell_m[idx2 % 64]) // div % 256
                        pairs.append(val)

                    if 119 in pairs:
                        if check_key(pairs, f"row_off_{row_off_before}_{row_off_after}_div{div}_m{mult40}_{mult53}"):
                            exit()

# ============================================================================
# Test 8: Combine the key findings
# Position 19 gives 119 with mult17/div7
# Let's output what we have at position 19 with various configs
# ============================================================================
print("\n[8] Analysis of position 19 (where we get 119)...")

print("\n  Standard pairing (shell[38] + shell[39]):")
for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        pair_sum = shell_m[38] + shell_m[39]
        print(f"    m{mult40}_{mult53}: sum={pair_sum}, /7={pair_sum//7}, /64={pair_sum//64}, /127={pair_sum//127}")
        print(f"             /7%256={pair_sum//7%256}, /64%256={pair_sum//64%256}, /127%256={pair_sum//127%256}")

print("\n  Shell values at indices 39 and 52 (where white lines are):")
print(f"    shell[39] = {shell[39]} (rect 40, 17px line)")
print(f"    shell[52] = {shell[52]} (rect 53, 6px line)")
print(f"    shell[39] / shell[52] = {shell[39] / shell[52]:.2f}")
print(f"    shell[39] * 17 = {shell[39] * 17}")
print(f"    shell[52] * 6 = {shell[52] * 6}")

print("\nMini-puzzle analysis complete.")
