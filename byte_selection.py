"""
What if the digit sequences tell us which bytes to SELECT?

09111819 -> select bytes at positions 0, 9, 11, 18, 19 (or as two-digit: 09, 11, 18, 19)
11122111 -> select bytes at positions 11, 12, 21, 11 (or as two-digit: 11, 12, 21, 11)

Or maybe the digits tell us how to CONSTRUCT the 32-byte key from
a larger pool of computed values.
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
print("BYTE SELECTION APPROACH")
print("="*70)

seq1 = [0, 9, 1, 1, 1, 8, 1, 9]
seq2 = [1, 1, 1, 2, 2, 1, 1, 1]

# ============================================================================
# 1. Compute a pool of 64 values and select 32 using digit sequence
# ============================================================================
print("\n[1] Computing 64-byte pool and selecting 32...")

shell_m = shell.copy()
shell_m[39] *= 17

# Pool: each shell value / 7
pool = [s // 7 % 256 for s in shell_m]
print(f"Pool first 10: {[hex(p) for p in pool[:10]]}")
print(f"Pool[39] = {hex(pool[39])}")  # Should be 0x77 with mult

# Different selection patterns
all_digits = seq1 + seq2

# Pattern 1: digits are absolute positions in pool
positions = []
for i, d in enumerate(all_digits):
    positions.append(d)
# Extend to 32 positions
extended_pos = (positions * 3)[:32]

pairs = [pool[p % 64] for p in extended_pos]
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Direct positions: first={hex(pairs[0])}, 0x77 at {has_77}")
if check_key(pairs, "direct_positions"):
    exit()

# Pattern 2: cumulative positions
positions = []
pos = 0
for d in all_digits:
    positions.append(pos % 64)
    pos += d if d > 0 else 1
# Extend
positions = (positions * 4)[:32]
pairs = [pool[p] for p in positions]
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Cumulative positions: first={hex(pairs[0])}, 0x77 at {has_77}")
if check_key(pairs, "cumulative_positions"):
    exit()

# ============================================================================
# 2. Two-digit numbers as positions: 09, 11, 18, 19, 11, 12, 21, 11
# ============================================================================
print("\n[2] Two-digit positions...")

two_digit = [9, 11, 18, 19, 11, 12, 21, 11]
extended = (two_digit * 4)[:32]

pairs = [pool[p % 64] for p in extended]
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Two-digit positions: first={hex(pairs[0])}, 0x77 at {has_77}")
if check_key(pairs, "two_digit_positions"):
    exit()

# Add FIX offset
pairs = [pool[(p + 39) % 64] for p in extended]
has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Two-digit + FIX(39): first={hex(pairs[0])}, 0x77 at {has_77}")
if check_key(pairs, "two_digit_fix39"):
    exit()

# ============================================================================
# 3. Each digit defines which of 2 pools to use
# ============================================================================
print("\n[3] Digit as pool selector...")

# Two pools: shell/7 and shell/10
pool7 = [s // 7 % 256 for s in shell_m]
pool10 = [s // 10 % 256 for s in shell_m]

pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    if digit < 5:
        pairs.append(pool7[i * 2])
    else:
        pairs.append(pool10[i * 2])

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Digit<5 uses pool7, else pool10: 0x77 at {has_77}")
if check_key(pairs, "pool_selector"):
    exit()

# ============================================================================
# 4. The 8 digits might define 8 "super-bytes" each computed from 4 rects
# ============================================================================
print("\n[4] 8 super-bytes from digit groups...")

for div in [7, 10]:
    super_bytes = []
    for i in range(8):
        d1 = seq1[i]
        d2 = seq2[i]

        # Use digits to compute this super-byte
        base_idx = i * 8

        # Sum 4 pairs of rects
        total = 0
        for j in range(4):
            idx1 = (base_idx + j * 2) % 64
            idx2 = (base_idx + j * 2 + 1) % 64
            total += shell_m[idx1] + shell_m[idx2]

        # Apply digit modifiers
        val = (total * d2 - d1) // div % 256
        super_bytes.append(val)

    # Expand to 32 bytes
    pairs = super_bytes * 4
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Super-bytes div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"super_bytes_div{div}"):
            exit()

# ============================================================================
# 5. Interleave bytes from different divisors
# ============================================================================
print("\n[5] Interleaved divisor bytes...")

pool7 = []
pool10 = []
for i in range(32):
    pool7.append((shell_m[i*2] + shell_m[i*2+1]) // 7 % 256)
    pool10.append((shell_m[i*2] + shell_m[i*2+1]) // 10 % 256)

# Interleave based on digit sequence
pairs = []
for i in range(32):
    digit = all_digits[i % 16]
    if digit % 2 == 0:
        pairs.append(pool7[i])
    else:
        pairs.append(pool10[i])

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Even digit->pool7, odd->pool10: first={hex(pairs[0])}, 0x77 at {has_77}")
if check_key(pairs, "interleaved_by_parity"):
    exit()

# ============================================================================
# 6. XOR between pool values based on digit pairing
# ============================================================================
print("\n[6] XOR pairing based on digits...")

for div in [7, 10]:
    pool = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        j = (i + digit) % 32
        val = pool[i] ^ pool[j]
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  XOR(i, i+digit) div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"xor_digit_div{div}"):
            exit()

# ============================================================================
# 7. Use digit sum (30, 10) as section divisors
# ============================================================================
print("\n[7] Section-based divisors (30, 10)...")

pairs = []
for i in range(32):
    if i < 16:
        div = 30
    else:
        div = 10
    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
    pairs.append(val)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  First 16: div30, last 16: div10: 0x77 at {has_77}")
if check_key(pairs, "section_div30_10"):
    exit()

# Reversed
pairs = []
for i in range(32):
    if i < 16:
        div = 10
    else:
        div = 30
    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
    pairs.append(val)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  First 16: div10, last 16: div30: 0x77 at {has_77}")
if check_key(pairs, "section_div10_30"):
    exit()

# ============================================================================
# 8. Try reading rectangles in a different order
# ============================================================================
print("\n[8] Alternative reading orders...")

# Column-major (8x8 grid read by columns)
pairs = []
for col in range(8):
    for row in range(4):  # Only need 32
        idx = row * 8 + col
        if len(pairs) < 32:
            pairs.append(pool[idx])

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Column-major: 0x77 at {has_77}")
if check_key(pairs, "column_major"):
    exit()

# Diagonal
pairs = []
for diag in range(8):
    for i in range(8):
        idx = (diag + i) % 8 * 8 + i
        if len(pairs) < 32 and idx < 64:
            pairs.append(pool[idx])

if len(pairs) == 32:
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  Diagonal: 0x77 at {has_77}")
    if check_key(pairs, "diagonal"):
        exit()

# ============================================================================
# 9. Maybe the key uses a running sum/XOR
# ============================================================================
print("\n[9] Running operations...")

pool7 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Running XOR
pairs = []
running = 0
for i in range(32):
    running ^= pool7[i]
    pairs.append(running)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Running XOR: 0x77 at {has_77}")
if check_key(pairs, "running_xor"):
    exit()

# Running sum mod 256
pairs = []
running = 0
for i in range(32):
    running = (running + pool7[i]) % 256
    pairs.append(running)

has_77 = [j for j,p in enumerate(pairs) if p==0x77]
print(f"  Running sum: 0x77 at {has_77}")
if check_key(pairs, "running_sum"):
    exit()

# ============================================================================
# 10. What if we need to subtract instead of add?
# ============================================================================
print("\n[10] Subtraction instead of addition...")

for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = abs(shell_m[i*2] - shell_m[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  |s1-s2| div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"subtract_div{div}"):
            exit()

# ============================================================================
# 11. Final attempt: systematic search with digit-based modifications
# ============================================================================
print("\n[11] Digit-based byte modifications...")

# Base key with good properties
base = pool7.copy()

# Each digit tells us how to modify the corresponding byte
for mod_type in ['add', 'xor', 'sub', 'mult']:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        b = base[i]

        if mod_type == 'add':
            pairs.append((b + digit * 17) % 256)
        elif mod_type == 'xor':
            pairs.append(b ^ (digit * 17))
        elif mod_type == 'sub':
            pairs.append((b - digit * 7) % 256)
        elif mod_type == 'mult':
            pairs.append((b * (digit + 1)) % 256)

    if check_key(pairs, f"digit_mod_{mod_type}"):
        exit()

print("\n" + "="*70)
print("Byte selection approaches complete")
print("="*70)
