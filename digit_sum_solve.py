"""
DIGIT SUMS CLUE:
- 09111819: 0+9+1+1+1+8+1+9 = 30
- 11122111: 1+1+1+2+2+1+1+1 = 10
- Total: 30 + 10 = 40 -> points to RECT 40 (the 17px line!)

Also:
- 30 / 10 = 3
- 30 - 10 = 20
- 30 * 10 = 300

Let's explore what these numbers mean!
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
print("DIGIT SUMS EXPLORATION")
print("="*70)
print("09111819 digit sum = 30")
print("11122111 digit sum = 10")
print("Total = 40 -> Rectangle 40!")
print("30/10 = 3, 30-10 = 20, 30*10 = 300")
print()

# ============================================================================
# Test 1: Use 30 and 10 as multipliers
# ============================================================================
print("[1] 30 and 10 as multipliers...")

for mult39 in [30, 17, 1]:
    for mult52 in [10, 6, 1]:
        shell_m = shell.copy()
        shell_m[39] *= mult39  # Rect 40 (0-indexed: 39)
        shell_m[52] *= mult52  # Rect 53 (0-indexed: 52)

        for div in [7, 10, 30, 40, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
            has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  m{mult39}_{mult52} div{div}: 0x77 at {has_77}")
                if check_key(pairs, f"m{mult39}_{mult52}_div{div}"):
                    exit()

# ============================================================================
# Test 2: Use 30 and 10 as divisors for different halves
# ============================================================================
print("\n[2] 30 for first 16 bytes, 10 for last 16 bytes...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = []
        for i in range(32):
            div = 30 if i < 16 else 10
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"split30_10_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# Test 3: Rectangles 30 and 10 are special
# ============================================================================
print("\n[3] Using rect indices 30 and 10 specially...")

# Maybe we start pairing from rect 30 or rect 10?
for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            # Start from rect 30
            pairs = []
            for i in range(32):
                idx = (30 + i * 2) % 64
                idx2 = (30 + i * 2 + 1) % 64
                val = (shell_m[idx] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Start30 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"start30_div{div}_m{mult39}_{mult52}"):
                    exit()

            # Start from rect 10
            pairs = []
            for i in range(32):
                idx = (10 + i * 2) % 64
                idx2 = (10 + i * 2 + 1) % 64
                val = (shell_m[idx] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Start10 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"start10_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 4: Skip by 30-10=20 or 30/10=3
# ============================================================================
print("\n[4] Skip patterns: 20 (30-10) and 3 (30/10)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for skip in [3, 20, 30, 10]:
            for div in [7, 64, 127]:
                pairs = []
                for i in range(32):
                    idx1 = i
                    idx2 = (i + skip) % 64
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
                if has_77:
                    print(f"  Skip{skip} div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                    if check_key(pairs, f"skip{skip}_div{div}_m{mult39}_{mult52}"):
                        exit()

# ============================================================================
# Test 5: 40 as the key number - divide by 40
# ============================================================================
print("\n[5] Divide by 40 (the total digit sum)...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 40 % 256 for i in range(32)]
        has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  div40 m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"div40_m{mult39}_{mult52}"):
                exit()

# ============================================================================
# Test 6: 30*10=300 as divisor
# ============================================================================
print("\n[6] Divide by 300 (30*10)...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = [(shell_m[i*2] + shell_m[i*2+1]) // 300 % 256 for i in range(32)]
        # Most values will be small since shell sums are typically 1000-4000
        print(f"  div300 m{mult39}_{mult52}: {pairs[:8]}...")
        if check_key(pairs, f"div300_m{mult39}_{mult52}"):
            exit()

# ============================================================================
# Test 7: Maybe rect 40 needs mult by digit sum (30), rect 53 by its related sum
# What's the digit sum relationship for rect 53?
# ============================================================================
print("\n[7] Rect 40 mult by 30, rect 53 mult by 10...")

shell_m = shell.copy()
shell_m[39] *= 30  # digit sum of first sequence
shell_m[52] *= 10  # digit sum of second sequence... but wait, 53 has 6px line

# Actually, maybe the 6px line relates to something else
# Let's try: rect 40 by 30, rect 53 by 6 (the pixel count)
shell_m2 = shell.copy()
shell_m2[39] *= 30
shell_m2[52] *= 6

for div in [7, 10, 30, 40, 64, 127]:
    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs) if p == 0x77]
    if has_77:
        print(f"  m30_10 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"m30_10_div{div}"):
            exit()

    pairs2 = [(shell_m2[i*2] + shell_m2[i*2+1]) // div % 256 for i in range(32)]
    has_77 = [i for i, p in enumerate(pairs2) if p == 0x77]
    if has_77:
        print(f"  m30_6 div{div}: 0x77 at {has_77}")
        if check_key(pairs2, f"m30_6_div{div}"):
            exit()

# ============================================================================
# Test 8: What if 30 means "use first 30 rects" and 10 means "use last 10"?
# ============================================================================
print("\n[8] First 30 rects + last 10 rects (40 total, but overlap)...")

# This doesn't quite work for 32 bytes, but let's try variations
for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            # First 15 bytes from first 30 rects, last 17 from remaining
            pairs = []
            # First 15 pairs from rects 0-29
            for i in range(15):
                idx1 = i * 2
                idx2 = i * 2 + 1
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)
            # Last 17 pairs from rects 30-63
            for i in range(17):
                idx1 = 30 + i * 2
                idx2 = 30 + i * 2 + 1
                if idx2 < 64:
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                else:
                    val = shell_m[idx1] // div % 256
                pairs.append(val)

            pairs = pairs[:32]
            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Split30_rest div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"split30_rest_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 9: 30+10=40, and 40 in hex is 0x28 - first byte?
# ============================================================================
print("\n[9] First byte should be 0x28 (40 in hex)?...")

for mult39 in [1, 17, 30]:
    for mult52 in [1, 6, 10]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Check if first byte is 0x28
            if pairs[0] == 0x28:
                print(f"  div{div} m{mult39}_{mult52}: First byte IS 0x28!")
                has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
                print(f"    0x77 at {has_77}")
                if check_key(pairs, f"first28_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 10: Apply digit sums as XOR pattern
# ============================================================================
print("\n[10] XOR with digit sums...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # XOR first 16 with 30, last 16 with 10
            pairs = []
            for i in range(32):
                if i < 16:
                    pairs.append(base[i] ^ 30)
                else:
                    pairs.append(base[i] ^ 10)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  XOR30_10 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"xor30_10_div{div}_m{mult39}_{mult52}"):
                    exit()

            # XOR all with 40
            pairs = [b ^ 40 for b in base]
            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  XOR40 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"xor40_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 11: 30 and 10 as row indices in 8x8 grid
# Row 30/8 = 3, Row 10/8 = 1
# ============================================================================
print("\n[11] Row-based interpretation (30->row3, 10->row1)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            # Read rows in order: row 3 (from 30), then row 1 (from 10), then others
            row_order = [3, 1, 0, 2, 4, 5, 6, 7]  # Start with rows 3 and 1
            reordered = []
            for row in row_order:
                for col in range(8):
                    reordered.append(shell_m[row * 8 + col])

            pairs = [(reordered[i*2] + reordered[i*2+1]) // div % 256 for i in range(32)]
            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  RowOrder div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"roworder_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 12: The formula with 30 and 10
# (-I * 30 + 64) / 10 or similar
# ============================================================================
print("\n[12] Formula variations with 30 and 10...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52
        inner_m[39] *= mult39
        inner_m[52] *= mult52

        # (-I * 30 + 64) / 10
        pairs = []
        for i in range(32):
            I = inner_m[i*2] + inner_m[i*2+1]
            result = abs((-I * 30 + 64) // 10) % 256
            pairs.append(result)

        has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
        if has_77:
            print(f"  (-I*30+64)/10 m{mult39}_{mult52}: 0x77 at {has_77}")
            if check_key(pairs, f"formula_30_10_m{mult39}_{mult52}"):
                exit()

        # (S * 30 + 64) / 10
        pairs = []
        for i in range(32):
            S = shell_m[i*2] + shell_m[i*2+1]
            result = (S * 30 + 64) // 10 % 256
            pairs.append(result)

        if check_key(pairs, f"S30_64_10_m{mult39}_{mult52}"):
            exit()

# ============================================================================
# Test 13: Pair rect i with rect (i+30)%64 for first half, (i+10)%64 for second
# ============================================================================
print("\n[13] Pair with +30 offset first half, +10 offset second half...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            pairs = []
            for i in range(32):
                if i < 16:
                    idx1 = i
                    idx2 = (i + 30) % 64
                else:
                    idx1 = i
                    idx2 = (i + 10) % 64

                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j, p in enumerate(pairs) if p == 0x77]
            if has_77:
                print(f"  Offset30_10 div{div} m{mult39}_{mult52}: 0x77 at {has_77}")
                if check_key(pairs, f"offset30_10_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Test 14: Digit sums point to byte positions where 0x77 should be
# Position 30 % 32 = 30, Position 10
# ============================================================================
print("\n[14] Set positions 30 and 10 to 0x77...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Set position 30 to 0x77
            pairs = base.copy()
            pairs[30] = 0x77
            if check_key(pairs, f"pos30_77_div{div}_m{mult39}_{mult52}"):
                exit()

            # Set position 10 to 0x77
            pairs = base.copy()
            pairs[10] = 0x77
            if check_key(pairs, f"pos10_77_div{div}_m{mult39}_{mult52}"):
                exit()

            # Set both
            pairs = base.copy()
            pairs[30] = 0x77
            pairs[10] = 0x77
            if check_key(pairs, f"pos30_10_77_div{div}_m{mult39}_{mult52}"):
                exit()

print("\nDigit sum exploration complete.")
