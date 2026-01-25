"""
Focus on the symbols:
- Lightning bolt (⚡) above FIX = XOR before
- Skull (💀) below FIX = subtract after
- -I *X+ LXIV /x/
- 09111819 FIX 11122111
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
print("SYMBOL-BASED SOLVER")
print("="*70)
print("Lightning above FIX = XOR operation")
print("Skull below FIX = subtract/death operation")
print("LXIV = 64")
print()

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]  # Before FIX
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]  # After FIX

# ============================================================================
# Interpretation: Lightning XOR, then FIX (divide by 64), then Skull subtract
# ============================================================================
print("[1] Lightning (XOR) -> FIX (div 64) -> Skull (subtract)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for xor_val in [0, 1, 64, 119, 127]:
            for sub_val in [0, 1, 64]:
                pairs = []
                for i in range(32):
                    # Lightning: XOR the pair values
                    xored = shell_m[i*2] ^ shell_m[i*2+1]
                    # FIX: divide by 64
                    fixed = xored // 64
                    # Skull: subtract
                    result = (fixed - sub_val) % 256
                    pairs.append(result)

                if 119 in pairs:
                    if check_key(pairs, f"xor_div64_sub{sub_val}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# FIX could mean "fix" by applying the sequence
# ============================================================================
print("\n[2] FIX as sequence application...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                base = (shell_m[i*2] + shell_m[i*2+1]) // div

                # Apply seq1 before FIX (first 16 bytes)
                # Apply seq2 after FIX (last 16 bytes)
                if i < 16:
                    modifier = seq1[i % 8]
                else:
                    modifier = seq2[(i - 16) % 8]

                # FIX could mean add/multiply/xor with modifier
                result = (base + modifier) % 256
                pairs.append(result)

            if 119 in pairs:
                if check_key(pairs, f"seq_add_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Try XOR with modifier
            pairs = []
            for i in range(32):
                base = (shell_m[i*2] + shell_m[i*2+1]) // div
                modifier = seq1[i % 8] if i < 16 else seq2[(i - 16) % 8]
                result = base ^ modifier
                pairs.append(result % 256)

            if 119 in pairs:
                if check_key(pairs, f"seq_xor_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# -I could mean use negative indexing or inverse
# ============================================================================
print("\n[3] -I as negative/inverse operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for div in [7, 64, 127]:
            # -I: subtract inner from outer (= shell, but computed)
            pairs = [(outer[i*2] - inner_m[i*2] + outer[i*2+1] - inner_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"neg_inner_div{div}_m{mult40}_{mult53}"):
                    exit()

            # -I: use inner with negation
            pairs = [((-inner_m[i*2] + shell_m[i*2]) + (-inner_m[i*2+1] + shell_m[i*2+1])) // div % 256 for i in range(32)]
            if check_key(pairs, f"neg_i_plus_s_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# *X+ could mean multiply by 10 (X in Roman) then add
# ============================================================================
print("\n[4] *X (times 10) plus operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # (S1 * 10) + S2, then divide
            pairs = [(shell_m[i*2] * 10 + shell_m[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"s1x10_plus_s2_div{div}_m{mult40}_{mult53}"):
                    exit()

            # S1 + (S2 * 10), then divide
            pairs = [(shell_m[i*2] + shell_m[i*2+1] * 10) // div % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"s1_plus_s2x10_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# /x/ with squiggle could be modular division or special rounding
# ============================================================================
print("\n[5] Special division operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Modulo instead of division
        for mod in [64, 127, 119]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) % mod for i in range(32)]
            if check_key(pairs, f"mod{mod}_m{mult40}_{mult53}"):
                exit()

        # Ceiling division
        import math
        for div in [7, 64, 127]:
            pairs = [math.ceil((shell_m[i*2] + shell_m[i*2+1]) / div) % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"ceil_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Complete formula: (-I) * X + LXIV / x
# ============================================================================
print("\n[6] Complete formula interpretation...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for x_val in [1, 7, 10, 64]:
            # (-I) * X + LXIV / x = (-inner) * X + 64 / X
            pairs = []
            for i in range(32):
                neg_i = -(inner_m[i*2] + inner_m[i*2+1])
                result = (neg_i * x_val + 64) // x_val
                pairs.append(abs(result) % 256)

            if 119 in pairs:
                if check_key(pairs, f"formula_x{x_val}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Maybe 09111819 and 11122111 are hex values
# ============================================================================
print("\n[7] Sequences as hex...")

# 09111819 in hex = 0x09111819 = 152114201
# 11122111 in hex = 0x11122111 = 286400785

hex1 = 0x09111819
hex2 = 0x11122111

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR with parts of hex values
            pairs = []
            for i in range(32):
                if i < 16:
                    xor_byte = (hex1 >> (8 * (i % 4))) & 0xFF
                else:
                    xor_byte = (hex2 >> (8 * ((i - 16) % 4))) & 0xFF
                pairs.append(base[i] ^ xor_byte)

            if 119 in pairs:
                if check_key(pairs, f"hex_xor_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# What if FIX means to fix specific bytes to 119?
# ============================================================================
print("\n[8] FIX as fixing bytes to 0x77...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Fix position 19 (where we get 119 with m17/div7)
            for num_fixes in range(1, 5):
                for positions in [[19], [19, 26], [0, 19], [19, 31], [0, 19, 31]]:
                    if len(positions) != num_fixes:
                        continue
                    pairs = base.copy()
                    for pos in positions:
                        if pos < 32:
                            pairs[pos] = 119
                    if check_key(pairs, f"fix119_pos{positions}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Lightning as power/exponent
# ============================================================================
print("\n[9] Lightning as power operation...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Power operation (small exponents to avoid overflow)
        for exp in [2, 3]:
            for div in [1000, 10000, 100000]:
                pairs = [pow(shell_m[i*2] + shell_m[i*2+1], exp) // div % 256 for i in range(32)]
                if 119 in pairs:
                    if check_key(pairs, f"pow{exp}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Skull as death/end - maybe truncate or use only part of result
# ============================================================================
print("\n[10] Skull as truncation/masking...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div for i in range(32)]

            # Mask with 0x7F (127)
            pairs = [b & 0x7F for b in base]
            if 119 in pairs:
                if check_key(pairs, f"mask7f_div{div}_m{mult40}_{mult53}"):
                    exit()

            # Mask with 0x77 (119)
            pairs = [b & 0x77 for b in base]
            if check_key(pairs, f"mask77_div{div}_m{mult40}_{mult53}"):
                exit()

print("\nSymbol-based search complete.")
