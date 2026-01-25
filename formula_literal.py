"""
Think about the formula more literally:
-I *X+ LXIV /x/

Roman numerals:
I = 1
X = 10
LXIV = 64
x = 10

So formula might be: (-1) * 10 + 64 / 10 = -10 + 6.4 = -3.6 (doesn't make sense)
Or: (val - 1) * 10 + 64, then / 10

Or stepwise:
1. Subtract I (1)
2. Multiply by X (10)
3. Add LXIV (64)
4. Divide by x (10)

val' = ((val - 1) * 10 + 64) / 10 = val - 1 + 6.4 = val + 5.4

Or maybe operations on indices?

Also think about the "following" and "non-consecutive" hints.
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

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]
all_digits = seq1 + seq2

def get_skip(digit):
    if digit == 0:
        return 1
    return digit

print("="*70)
print("FORMULA LITERAL INTERPRETATION")
print("="*70)

# ============================================================================
# 1. Apply formula: (val - 1) * 10 + 64, then / 10
# ============================================================================
print("\n[1] Formula: ((val - 1) * 10 + 64) / 10 = val + 5.4...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        raw = shell_m[idx1] + shell_m[idx2]
        # Apply formula
        val = ((raw - 1) * 10 + 64) // 10 // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Formula v1 div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"formula_v1_div{div}"):
            exit()

# ============================================================================
# 2. Maybe the formula is per-byte: ((sum/div) - 1) * 10 + 64) / 10
# ============================================================================
print("\n[2] Per-byte formula application...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        raw = (shell_m[idx1] + shell_m[idx2]) // div
        # Apply formula to the result
        val = ((raw - 1) * 10 + 64) // 10 % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Per-byte formula div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"perbyte_formula_div{div}"):
            exit()

# ============================================================================
# 3. Maybe -I means index, *X means multiply by 10, +64, /10
#    So: ((sum at (idx-1)) * 10 + 64) / 10
# ============================================================================
print("\n[3] Index-based formula: use (idx-1)...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        # -I: use index i-1
        idx = (i - 1) % 32
        idx1 = idx * 2
        idx2 = idx * 2 + 1
        raw = shell_m[idx1] + shell_m[idx2]
        # *X + LXIV / x: * 10 + 64, / 10
        val = (raw * 10 + 64) // 10 // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Index-1 formula div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"idx_minus1_div{div}"):
            exit()

# ============================================================================
# 4. What if the X's are different? /x/ might mean /10/ = divide by 10
#    But there's also X = 10 in Roman numerals
# ============================================================================
print("\n[4] Various X interpretations...")

shell_m = shell.copy()
shell_m[39] *= 17

# Try: sum * 10 + 64, then divide by specific values
for outer_div in [10, 70, 100, 640]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        raw = shell_m[idx1] + shell_m[idx2]
        val = (raw * 10 + 64) // outer_div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  (sum*10+64)/{outer_div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"formula_x10p64_d{outer_div}"):
            exit()

# ============================================================================
# 5. What if 64 is added to each pair sum, then divided?
# ============================================================================
print("\n[5] Add 64 to pair sum...")

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10, 17]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        raw = shell_m[idx1] + shell_m[idx2] + 64
        val = raw // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  (sum+64)/{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"sum_p64_d{div}"):
            exit()

# ============================================================================
# 6. Focus on the "following" sequence more carefully
#    What if digits encode a walk through the 64 rects?
# ============================================================================
print("\n[6] Digit-guided walk through rects...")

shell_m = shell.copy()
shell_m[39] *= 17

# Start at rect 0, use digits to determine next rect
for start in [0, 39, 52]:
    for div in [7, 10]:
        pairs = []
        pos = start
        for i in range(32):
            digit = all_digits[i % 16]
            step = digit if digit > 0 else 1

            # Get value from current position
            val = shell_m[pos] // div % 256
            pairs.append(val)

            # Move to next position
            pos = (pos + step) % 64

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  Walk from {start} div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
            if check_key(pairs, f"walk_start{start}_div{div}"):
                exit()

# ============================================================================
# 7. Maybe 39 and 52 are BOTH special
#    Apply different multipliers to both
# ============================================================================
print("\n[7] Both rect 39 and 52 with multipliers...")

for m39 in [1, 7, 17]:
    for m52 in [1, 6, 7]:
        shell_m = shell.copy()
        shell_m[39] *= m39
        shell_m[52] *= m52

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                digit = all_digits[i % 16]
                skip = get_skip(digit)
                idx1 = i * 2
                idx2 = (i * 2 + skip) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            if pairs[0] == 0x28 and has_77:
                print(f"  m39={m39}, m52={m52}, div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
                if check_key(pairs, f"m39_{m39}_m52_{m52}_div{div}"):
                    exit()

# ============================================================================
# 8. What if we need to apply the 17*7=119 constraint directly?
#    Position 19 should have value 119 = 17*7
# ============================================================================
print("\n[8] Force byte 19 to be 119...")

# Get base key
shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    digit = all_digits[i % 16]
    skip = get_skip(digit)
    idx1 = i * 2
    idx2 = (i * 2 + skip) % 64
    val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    base.append(val)

print(f"Base[19] = {base[19]} (0x{base[19]:02x})")

# It's already 0x77 = 119! But key doesn't work.
# Try forcing other bytes to satisfy constraints

# ============================================================================
# 9. The address "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7" - any hints?
# ============================================================================
print("\n[9] Address analysis...")

addr = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"
print(f"Address: {addr}")
print(f"Length: {len(addr)}")

# Decode base58 to get the hash160
import base58
decoded = base58.b58decode(addr)
print(f"Decoded (with version and checksum): {decoded.hex()}")
# First byte is version (0x00), last 4 bytes are checksum
version = decoded[0]
hash160 = decoded[1:21]
checksum = decoded[21:]
print(f"Version: {version}")
print(f"Hash160: {hash160.hex()}")
print(f"Checksum: {checksum.hex()}")

# ============================================================================
# 10. What if we need to find a key that produces this exact hash160?
#     This is what we're doing, but let's verify our method
# ============================================================================
print("\n[10] Verify base key produces different address...")

base_bytes = bytes(base)
addr_from_base = privkey_to_address(base_bytes, True)
print(f"Base key address: {addr_from_base}")

# ============================================================================
# 11. Try simpler patterns - maybe we're overcomplicating
# ============================================================================
print("\n[11] Simpler patterns...")

# Just consecutive pairs without skip
shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10, 17]:
    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  Simple consecutive div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"simple_div{div}"):
            exit()

# Just shell values directly
for div in [7, 10]:
    # First 32 shells
    pairs = [s // div % 256 for s in shell_m[:32]]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  First 32 shells div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"first32_div{div}"):
            exit()

    # Last 32 shells
    pairs = [s // div % 256 for s in shell_m[32:]]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Last 32 shells div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"last32_div{div}"):
            exit()

    # Every other shell
    pairs = [shell_m[i*2] // div % 256 for i in range(32)]
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Even shells div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"even_div{div}"):
            exit()

# ============================================================================
# 12. What if 09111819 and 11122111 are indices?
# ============================================================================
print("\n[12] Digit sequences as direct indices...")

# Use digits as indices into shell
for mult39 in [1, 17]:
    shell_m = shell.copy()
    shell_m[39] *= mult39

    for div in [7, 10, 1]:
        pairs = []
        for i in range(32):
            digit = all_digits[i % 16]
            # Use digit as additional index offset
            idx = (i * 2 + digit) % 64
            val = shell_m[idx] // div % 256
            pairs.append(val)

        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  Digit as offset m{mult39} div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"digit_offset_m{mult39}_div{div}"):
                exit()

# ============================================================================
# 13. Try different interpretations of the 8-digit pattern
# ============================================================================
print("\n[13] 8-position patterns...")

# The 8 digits might define 8 PAIRS of bytes
shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(8):
        d1 = seq1[i]
        d2 = seq2[i]

        # 4 bytes per digit pair
        for j in range(4):
            base_idx = i * 8 + j * 2
            idx1 = base_idx % 64
            idx2 = (base_idx + 1) % 64
            val = (shell_m[idx1] + shell_m[idx2]) // div % 256
            pairs.append(val)

    if len(pairs) == 32:
        has_77 = [j for j,p in enumerate(pairs) if p==0x77]
        if has_77:
            print(f"  8-pair pattern div{div}: 0x77 at {has_77}")
            if check_key(pairs, f"8pair_div{div}"):
                exit()

print("\n" + "="*70)
print("Still searching...")
print("="*70)

# Print best candidate
print(f"\nBest known candidate:")
print(f"Hex: {bytes(base).hex()}")
print(f"First: 0x28, 0x77 at [19]")
print(f"Address: {addr_from_base}")
