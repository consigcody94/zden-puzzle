"""
Insights from other Zden puzzles:
1. "1BiTCoiN WHiTe PaPeR" used a "6 px correction factor"
2. XIXOIO used bit interleaving: B1B2A1A2A3A4B3B4

For Level 5:
- 17px line under rect 40 -> correction factor?
- 6px line under rect 53 -> correction factor?

Maybe 17 and 6 are ADDITIVE corrections, not multipliers!
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
print("CORRECTION FACTOR SOLVER")
print("="*70)
print("Based on '6 px correction factor' from WhiTe PaPeR puzzle")
print("17px and 6px might be ADDITIVE corrections")
print()

# ============================================================================
# Test 1: Additive corrections instead of multiplicative
# ============================================================================
print("[1] Additive corrections to rect 39 and 52...")

for add39 in [17, 17*17, 17*shell[39], -17, 0]:
    for add52 in [6, 6*6, 6*shell[52], -6, 0]:
        shell_m = shell.copy()
        shell_m[39] += add39
        shell_m[52] += add52

        for div in [7, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            if 119 in pairs:
                if check_key(pairs, f"add39={add39}_add52={add52}_div{div}"):
                    exit()

# ============================================================================
# Test 2: Correction applied to ALL areas
# ============================================================================
print("\n[2] Global correction factor to all areas...")

for correction in [6, 17, 23, -6, -17]:
    shell_m = [s + correction for s in shell]

    for div in [7, 64, 127]:
        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

        if 119 in pairs:
            if check_key(pairs, f"global_correction{correction}_div{div}"):
                exit()

# ============================================================================
# Test 3: XIXOIO-style bit interleaving
# B1B2A1A2A3A4B3B4 - bits from two sources interleaved
# ============================================================================
print("\n[3] Bit interleaving like XIXOIO (B1B2A1A2A3A4B3B4)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Get values for each pair
            pairs = []
            for i in range(32):
                A = (shell_m[i * 2] // div) & 0xFF  # First rect -> A bits
                B = (shell_m[i * 2 + 1] // div) & 0xFF  # Second rect -> B bits

                # Interleave: B1B2A1A2A3A4B3B4
                # B1 = bit 7, B2 = bit 6, A1-A4 = bits 5-2, B3B4 = bits 1-0
                B1 = (B >> 7) & 1
                B2 = (B >> 6) & 1
                B3 = (B >> 5) & 1
                B4 = (B >> 4) & 1
                A1 = (A >> 3) & 1
                A2 = (A >> 2) & 1
                A3 = (A >> 1) & 1
                A4 = A & 1

                byte_val = (B1 << 7) | (B2 << 6) | (A1 << 5) | (A2 << 4) | (A3 << 3) | (A4 << 2) | (B3 << 1) | B4
                pairs.append(byte_val)

            if 119 in pairs:
                if check_key(pairs, f"interleave_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 4: Simpler bit interleaving: alternating bits
# ============================================================================
print("\n[4] Alternating bit interleaving...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                A = (shell_m[i * 2] // div) & 0xFF
                B = (shell_m[i * 2 + 1] // div) & 0xFF

                # Alternating bits: A0B0A1B1A2B2A3B3
                byte_val = 0
                for bit in range(4):
                    a_bit = (A >> bit) & 1
                    b_bit = (B >> bit) & 1
                    byte_val |= (a_bit << (bit * 2))
                    byte_val |= (b_bit << (bit * 2 + 1))
                pairs.append(byte_val)

            if 119 in pairs:
                if check_key(pairs, f"alt_bits_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 5: 17 and 6 define bit positions
# ============================================================================
print("\n[5] 17 and 6 as bit position indicators...")

# 17 in binary = 10001 (bits 0 and 4)
# 6 in binary = 110 (bits 1 and 2)

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                val = (shell_m[i * 2] + shell_m[i * 2 + 1]) // div

                # Mask with 17 (bits 0,4) and 6 (bits 1,2)
                masked = (val & 17) | ((val >> 4) & 6)
                pairs.append(masked % 256)

            if 119 in pairs:
                if check_key(pairs, f"mask17_6_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 6: The 6px correction might push towards center (like WhiTe PaPeR)
# ============================================================================
print("\n[6] Correction pushing towards center (middle value)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Find center value
        center = sum(shell_m) // 64

        for correction in [6, 17, 23]:
            for div in [7, 64, 127]:
                pairs = []
                for i in range(32):
                    val1 = shell_m[i * 2]
                    val2 = shell_m[i * 2 + 1]

                    # Push towards center by correction amount
                    if val1 > center:
                        val1 -= correction
                    else:
                        val1 += correction

                    if val2 > center:
                        val2 -= correction
                    else:
                        val2 += correction

                    pairs.append((val1 + val2) // div % 256)

                if 119 in pairs:
                    if check_key(pairs, f"center_corr{correction}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 7: XOR with 17 and 6
# ============================================================================
print("\n[7] XOR operations with 17 and 6...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR with 17
            pairs = [b ^ 17 for b in base]
            if 119 in pairs:
                if check_key(pairs, f"xor17_div{div}_m{mult40}_{mult53}"):
                    exit()

            # XOR with 6
            pairs = [b ^ 6 for b in base]
            if 119 in pairs:
                if check_key(pairs, f"xor6_div{div}_m{mult40}_{mult53}"):
                    exit()

            # XOR with 17*6 = 102
            pairs = [b ^ 102 for b in base]
            if 119 in pairs:
                if check_key(pairs, f"xor102_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 8: 17 and 6 define pairing relationship
# Rect i pairs with rect (i + 17) or (i + 6)
# ============================================================================
print("\n[8] 17 and 6 as pairing offsets...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for offset in [17, 6, 17+6, 17-6]:
            for div in [7, 64, 127]:
                pairs = []
                for i in range(32):
                    idx1 = i
                    idx2 = (i + offset) % 64
                    pairs.append((shell_m[idx1] + shell_m[idx2]) // div % 256)

                if 119 in pairs:
                    if check_key(pairs, f"offset{offset}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Test 9: Rect 39 and 52 define the "following" pattern
# ============================================================================
print("\n[9] Rect 39 and 52 values as pattern indicators...")

# shell[39] = 839, shell[52] = 118
# 839 / 118 = 7.1... (close to 7)
# Maybe the "following" means skip by 7?

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        skip = shell[39] // shell[52]  # = 7

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                idx1 = i
                idx2 = (i + skip) % 64
                pairs.append((shell_m[idx1] + shell_m[idx2]) // div % 256)

            if 119 in pairs:
                if check_key(pairs, f"skip{skip}_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 10: Apply correction only to specific byte positions
# Maybe bytes at positions 19 (where we get 119) and 26 (52/2) are special
# ============================================================================
print("\n[10] Byte position 19 and 26 special handling...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Position 19 should be 119 (we know this from earlier tests)
            # What about position 26 (rect 52 / 2)?
            print(f"  div{div} m{mult40}_{mult53}: byte[19]={base[19]}, byte[26]={base[26]}")

            # Try setting position 26 to 119 as well
            pairs = base.copy()
            pairs[19] = 119
            pairs[26] = 119
            if check_key(pairs, f"fix19_26_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 11: Divisor 64 with various corrections
# Since LXIV = 64 is prominently featured
# ============================================================================
print("\n[11] LXIV (64) focused with corrections...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for correction in range(-10, 11):
            pairs = [(shell_m[i*2] + shell_m[i*2+1] + correction) // 64 % 256 for i in range(32)]

            if 119 in pairs:
                pos = [j for j, v in enumerate(pairs) if v == 119]
                print(f"  correction={correction} m{mult40}_{mult53}: 119 at {pos}")
                if check_key(pairs, f"lxiv_corr{correction}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 12: Hex digits with 64 as divisor
# ============================================================================
print("\n[12] Hex digit approach with LXIV = 64...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Each shell / 64 gives hex digit (0-15 range)
        hex_digits = [s // 64 % 16 for s in shell_m]

        # Pair as D1*16 + D2
        pairs = [hex_digits[i*2] * 16 + hex_digits[i*2+1] for i in range(32)]

        print(f"  hex64 m{mult40}_{mult53}: {[hex(p) for p in pairs[:8]]}... 0x77 at {[j for j,v in enumerate(pairs) if v==0x77]}")

        if 0x77 in pairs:
            if check_key(pairs, f"hex64_m{mult40}_{mult53}"):
                exit()

print("\nCorrection factor search complete.")
