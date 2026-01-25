"""
Deeper formula interpretation:
-I = subtract Inner (not just -1!)
*X+ = multiply by X (unknown) and add
LXIV = 64
/x/ = divide by x

Lightning bolt = XOR operation
Skull = subtract/end

09111819 FIX 11122111
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

shell = [r[2] for r in RECT_DATA]  # Outer - Inner = Shell
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
print("FORMULA SOLVER: -I *X+ LXIV /x/")
print("="*70)

# ============================================================================
# -I means Outer - Inner (which equals Shell!)
# But maybe it means to use Outer - Inner in a specific way
# ============================================================================
print("\n[1] -I as (Outer - Inner) operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        # -I could mean we use the difference Outer - Inner
        # But that's just Shell... unless we need to compute it differently

        outer_m = outer.copy()
        inner_m = inner.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        # (O1 - I1) + (O2 - I2) / 64
        pairs = [((outer_m[i*2] - inner_m[i*2]) + (outer_m[i*2+1] - inner_m[i*2+1])) // 64 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  O-I pairs div64 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"o_minus_i_div64_m{mult40}_{mult53}"):
            exit()

        # O1 - I2 (cross subtraction)
        pairs = [(outer_m[i*2] - inner_m[i*2+1]) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"o1_minus_i2_div64_m{mult40}_{mult53}"):
            exit()

        # (O1 + O2) - (I1 + I2) / 64
        pairs = [((outer_m[i*2] + outer_m[i*2+1]) - (inner_m[i*2] + inner_m[i*2+1])) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"osum_minus_isum_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# *X+ could mean multiply by 10 (Roman X) and add
# ============================================================================
print("\n[2] *X (times 10) operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # (S1 * 10 + S2) / 64
        pairs = [(shell_m[i*2] * 10 + shell_m[i*2+1]) // 64 % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  S1*10+S2 div64 m{mult40}_{mult53}: contains 119")
        if check_key(pairs, f"s1_times10_plus_s2_div64_m{mult40}_{mult53}"):
            exit()

        # (S1 + S2) * 10 / 64
        pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 10) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"sum_times10_div64_m{mult40}_{mult53}"):
            exit()

        # S1 * 10 + S2 * 10 / 64 (same as above but explicit)
        pairs = [(shell_m[i*2] * 10 + shell_m[i*2+1] * 10) // 64 % 256 for i in range(32)]
        if check_key(pairs, f"both_times10_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# Lightning bolt XOR before/after FIX
# Skull subtract before/after FIX
# ============================================================================
print("\n[3] Lightning (XOR) and Skull (subtract) around FIX...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Lightning above = XOR before operation
        # Skull below = subtract after operation
        for xor_val in [1, 10, 64, 119]:
            for sub_val in [0, 1, 10]:
                pairs = [((shell_m[i*2] ^ shell_m[i*2+1]) // 64 - sub_val) % 256 for i in range(32)]
                if 119 in pairs:
                    if check_key(pairs, f"xor_div64_sub{sub_val}_m{mult40}_{mult53}"):
                        exit()

        # XOR with the result
        for xor_val in [64, 119, 0x77]:
            pairs = [((shell_m[i*2] + shell_m[i*2+1]) // 64) ^ xor_val for i in range(32)]
            pairs = [p % 256 for p in pairs]
            if check_key(pairs, f"sum_div64_xor{xor_val}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# 09111819 could be read as: 0,9,11,18,19 (positions)
# Or as operation codes
# ============================================================================
print("\n[4] Sequence 09111819 as positions...")

positions_interp1 = [0, 9, 11, 18, 19]  # Reading as multi-digit
positions_interp2 = [0, 9, 1, 1, 1, 8, 1, 9]  # Single digits

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        base = [(shell_m[i*2] + shell_m[i*2+1]) // 64 % 256 for i in range(32)]

        # Interpretation 1: These positions get special treatment
        for special_val in [119, 0x77, 64]:
            pairs = base.copy()
            for pos in positions_interp1:
                if pos < 32:
                    pairs[pos] = special_val
            if check_key(pairs, f"pos_special_{special_val}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# 11122111 after FIX could indicate: 1,1,1,2,2,1,1,1
# Maybe these are the pairing offsets AFTER applying FIX
# ============================================================================
print("\n[5] Post-FIX sequence 11122111...")

seq_after = [1, 1, 1, 2, 2, 1, 1, 1]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Use seq_after as pairing offsets
        pairs = []
        for i in range(32):
            offset = seq_after[i % 8]
            idx1 = i * 2
            idx2 = (i * 2 + offset) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // 64 % 256
            pairs.append(val)

        if 119 in pairs:
            if check_key(pairs, f"post_fix_offset_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# FIX could mean: swap or correct certain pairs
# ============================================================================
print("\n[6] FIX as swap operation...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # FIX might mean swap the order based on some condition
        pairs = []
        for i in range(32):
            a, b = shell_m[i*2], shell_m[i*2+1]
            # "Fix" by putting larger first
            if b > a:
                a, b = b, a
            val = (a + b) // 64 % 256
            pairs.append(val)

        if check_key(pairs, f"fix_sorted_div64_m{mult40}_{mult53}"):
            exit()

        # Or fix by XOR condition
        pairs = []
        for i in range(32):
            a, b = shell_m[i*2], shell_m[i*2+1]
            if (a ^ b) & 1:  # If XOR is odd, swap
                a, b = b, a
            val = (a + b) // 64 % 256
            pairs.append(val)

        if check_key(pairs, f"fix_xor_swap_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# /x/ could be integer division or absolute division
# The squiggle might indicate special rounding
# ============================================================================
print("\n[7] Different division styles...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Round to nearest instead of floor
        pairs = [round((shell_m[i*2] + shell_m[i*2+1]) / 64) % 256 for i in range(32)]
        if 119 in pairs:
            if check_key(pairs, f"round_div64_m{mult40}_{mult53}"):
                exit()

        # Ceiling division
        import math
        pairs = [math.ceil((shell_m[i*2] + shell_m[i*2+1]) / 64) % 256 for i in range(32)]
        if check_key(pairs, f"ceil_div64_m{mult40}_{mult53}"):
            exit()

# ============================================================================
# What if the formula is read right to left (reverse)?
# /x/ LXIV +X* I-
# ============================================================================
print("\n[8] Reverse formula reading...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # (sum / x) * 64 + 10 * ? - I
        # Try: sum / 64 then operations
        for x in [1, 2, 4, 8]:
            pairs = [(((shell_m[i*2] + shell_m[i*2+1]) // x) + 64 * 10 - 1) % 256 for i in range(32)]
            if check_key(pairs, f"reverse_x{x}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Full symbolic interpretation
# ============================================================================
print("\n[9] Symbolic: -I (negative Inner), *X+ (mult X add), LXIV, /x/...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        outer_m = outer.copy()
        inner_m = inner.copy()
        shell_m = shell.copy()
        outer_m[39] *= mult40
        outer_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # -I: use negative of inner, *X+: mult by X and add something
        # Formula: (-Inner * X + something) / 64
        for x_val in [1, 2, 10]:
            for add_val in [0, outer_m[0], shell_m[0]]:
                pairs = []
                for i in range(32):
                    neg_inner = -inner_m[i*2]
                    result = neg_inner * x_val + inner_m[i*2+1]
                    result = abs(result) // 64 % 256
                    pairs.append(result)

                if 119 in pairs:
                    if check_key(pairs, f"neg_inner_x{x_val}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Try with the 17*7=119 relationship and div 64
# ============================================================================
print("\n[10] 17*7=119 with div 64...")

for mult53 in [1, 6, 7]:
    shell_m = shell.copy()
    shell_m[39] *= 17  # Always use 17 for rect 40
    shell_m[52] *= mult53

    # (sum * 17 * 7) / (64 * 119) - trying to get 119 naturally
    pairs = [((shell_m[i*2] + shell_m[i*2+1]) * 17 * 7) // (64 * 119) % 256 for i in range(32)]
    if check_key(pairs, f"17x7_div64x119_m17_{mult53}"):
        exit()

    # Or simpler: sum / 64, looking for natural 119s
    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 64 % 256 for i in range(32)]
    print(f"  m17_{mult53} div64: {pairs}")
    if 119 in pairs:
        print(f"    ^ Contains 119 at {[i for i,v in enumerate(pairs) if v==119]}")

# ============================================================================
# What if we need to use ONLY certain rectangles based on sequence?
# ============================================================================
print("\n[11] Selective rectangle use...")

seq = [0, 9, 1, 1, 1, 8, 1, 9, 1, 1, 1, 2, 2, 1, 1, 1]  # Full sequence

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Use sequence digits as rectangle indices
        pairs = []
        for i in range(32):
            # Get two indices from sequence
            idx1 = seq[i % 16]
            idx2 = seq[(i + 1) % 16]
            # Scale up to cover all 64
            idx1 = (idx1 * 4 + i) % 64
            idx2 = (idx2 * 4 + i + 1) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // 64 % 256
            pairs.append(val)

        if 119 in pairs:
            if check_key(pairs, f"seq_indices_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Lightning and Skull as binary flags per byte
# ============================================================================
print("\n[12] Lightning/Skull as byte modifiers...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        base = [(shell_m[i*2] + shell_m[i*2+1]) // 64 % 256 for i in range(32)]

        # Apply XOR to first half (above FIX = lightning)
        # Apply subtract to second half (below FIX = skull)
        pairs = []
        for i in range(32):
            if i < 16:
                # Lightning = XOR with something
                val = base[i] ^ 64
            else:
                # Skull = subtract something
                val = (base[i] - 1) % 256
            pairs.append(val)

        if 119 in pairs:
            if check_key(pairs, f"light_skull_split_m{mult40}_{mult53}"):
                exit()

print("\nFormula solver complete.")
