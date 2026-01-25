"""
BEST FINDING: PairMatch with div7, m17 gives:
- First byte = 0x28 (40 = digit sum total!)
- 0x77 at position 19

The digit sequence defines the skip:
- 0 -> consecutive (skip 1)
- 9 -> skip 9
- 8 -> skip 8 (next row in 8x8 grid)
- 1 -> consecutive (skip 1)
- 2 -> skip 2

Let's explore this pattern more deeply!
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

def get_skip(digit):
    """Convert digit to skip value"""
    if digit == 0:
        return 1  # 0 means consecutive
    return digit

print("="*70)
print("PAIRMATCH DEEP EXPLORATION")
print("="*70)

# ============================================================================
# Output the base PairMatch key
# ============================================================================
print("[1] Base PairMatch key (div7, m17)...")

shell_m = shell.copy()
shell_m[39] *= 17

pairs = []
all_digits = seq1 + seq2  # 16 digits
for i in range(32):
    digit = all_digits[i % 16]
    skip = get_skip(digit)
    idx1 = i * 2
    idx2 = (i * 2 + skip) % 64
    val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
    pairs.append(val)

print(f"  Hex: {''.join(f'{p:02x}' for p in pairs)}")
print(f"  First byte: {hex(pairs[0])}")
print(f"  0x77 at: {[i for i,p in enumerate(pairs) if p==0x77]}")
print(f"  Bytes: {pairs}")
check_key(pairs, "pairmatch_div7_m17")

# ============================================================================
# Try variations on the skip mapping
# ============================================================================
print("\n[2] Alternative skip mappings...")

# Maybe 0 means skip 0 (same rect twice)?
def get_skip_v2(digit):
    return digit  # 0 means skip 0

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10, 64]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip_v2(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 or has_77:
        print(f"  V2 (0=0) div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"pairmatch_v2_div{div}"):
            exit()

# ============================================================================
# Try with 6px multiplier at rect 52
# ============================================================================
print("\n[3] Add 6px multiplier at rect 52...")

for mult52 in [1, 6]:
    shell_m = shell.copy()
    shell_m[39] *= 17
    shell_m[52] *= mult52

    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // 7 % 256
        pairs.append(val)

    print(f"  m17_{mult52}: first={hex(pairs[0])}, 0x77 at {[j for j,p in enumerate(pairs) if p==0x77]}")
    if check_key(pairs, f"pairmatch_m17_{mult52}"):
        exit()

# ============================================================================
# Try different digit-to-skip interpretations
# ============================================================================
print("\n[4] Different digit interpretations...")

# Maybe the digit is the row offset in 8x8 grid?
# skip = digit * 8 (move down by digit rows)
def get_skip_row(digit):
    if digit == 0:
        return 1
    return digit * 8 if digit < 8 else digit

shell_m = shell.copy()
shell_m[39] *= 17

for div in [7, 10]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip_row(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (shell_m[idx1] + shell_m[idx2]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  RowSkip div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"rowskip_div{div}"):
            exit()

# ============================================================================
# Try with formula applied: (sum * X + 64) / 7
# ============================================================================
print("\n[5] PairMatch with formula (sum + 64) / 7...")

shell_m = shell.copy()
shell_m[39] *= 17

for add_val in [0, 32, 64, -32, -64]:
    pairs = []
    for i in range(32):
        digit = all_digits[i % 16]
        skip = get_skip(digit)
        idx1 = i * 2
        idx2 = (i * 2 + skip) % 64
        val = (shell_m[idx1] + shell_m[idx2] + add_val) // 7 % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if pairs[0] == 0x28 and has_77:
        print(f"  Add{add_val}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"pairmatch_add{add_val}"):
            exit()

# ============================================================================
# Brute force single byte modification on PairMatch key
# ============================================================================
print("\n[6] Single byte modification on PairMatch key...")

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

for pos in range(32):
    for val in range(256):
        pairs = base.copy()
        pairs[pos] = val
        if check_key(pairs, f"mod_pos{pos}_val{val}"):
            exit()

print("  Single byte mod: no solution")

# ============================================================================
# Try reversing or reordering
# ============================================================================
print("\n[7] Byte ordering variations...")

# Reverse
pairs = base[::-1]
if check_key(pairs, "pairmatch_reversed"):
    exit()

# Swap halves
pairs = base[16:] + base[:16]
if check_key(pairs, "pairmatch_swapped"):
    exit()

# Nibble swap each byte
pairs = [((b & 0x0F) << 4) | ((b >> 4) & 0x0F) for b in base]
if check_key(pairs, "pairmatch_nibbleswap"):
    exit()

print("  Ordering variations: no solution")

# ============================================================================
# Try XOR with key constants
# ============================================================================
print("\n[8] XOR with constants...")

for xor_val in [0x28, 0x40, 0x77, 39, 52, 17, 6]:
    pairs = [b ^ xor_val for b in base]
    if check_key(pairs, f"pairmatch_xor{xor_val}"):
        exit()

print("  XOR variations: no solution")

# ============================================================================
# Two-byte modification at key positions
# ============================================================================
print("\n[9] Two-byte modification at key positions...")

key_positions = [0, 16, 19, 31]
count = 0

for p1 in key_positions:
    for p2 in key_positions:
        if p1 >= p2:
            continue
        for v1 in range(256):
            for v2 in range(256):
                pairs = base.copy()
                pairs[p1] = v1
                pairs[p2] = v2
                if check_key(pairs, f"2byte_{p1}_{p2}_{v1}_{v2}"):
                    exit()
                count += 1

print(f"  Checked {count} two-byte modifications: no solution")

print("\n" + "="*70)
print("FINAL KEY CANDIDATE")
print("="*70)
print(f"Method: PairMatch with digit-defined skips, div7, m17")
print(f"Hex: {''.join(f'{p:02x}' for p in base)}")
print(f"First byte: {hex(base[0])} (= {base[0]} = 40 = digit sum total!)")
print(f"0x77 position: {[i for i,p in enumerate(base) if p==0x77]}")
