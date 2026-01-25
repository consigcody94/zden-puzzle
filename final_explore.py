"""
Best candidates so far:
1. Div7, m17: first=0x28, 0x77 at pos 19
2. Split div7/div10, m17: first=0x28, 0x77 at pos 16

The digit sum hints:
- 30 (first sequence) -> div 7 makes sense (30/7 ~= 4.3)
- 10 (second sequence) -> div 10 directly!
- 40 (total) -> first byte 0x28 = 40

Let's try more split patterns and byte modifications.
"""
import hashlib
import ecdsa
import base58
import itertools

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
print("FINAL EXPLORATION")
print("="*70)

# Best base: split div7/div10 with mult17
shell_m = shell.copy()
shell_m[39] *= 17

first16 = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(16)]
last16 = [(shell_m[(16+i)*2] + shell_m[(16+i)*2+1]) // 10 % 256 for i in range(16)]
base = first16 + last16

print("Base key (split div7/div10, m17):")
print(f"  Hex: {''.join(f'{p:02x}' for p in base)}")
print(f"  First byte: {hex(base[0])}, 0x77 at: {[i for i,p in enumerate(base) if p==0x77]}")

# ============================================================================
# Try different split points
# ============================================================================
print("\n[1] Different split points for div7/div10...")

for split_at in range(8, 25):
    for mult39 in [1, 17]:
        shell_m = shell.copy()
        shell_m[39] *= mult39

        pairs = []
        for i in range(32):
            div = 7 if i < split_at else 10
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if pairs[0] == 0x28 and 0x77 in pairs:
            if check_key(pairs, f"split{split_at}_m{mult39}"):
                exit()

# ============================================================================
# Try using 30 as first divisor, 10 as second
# ============================================================================
print("\n[2] Split with div30/div10...")

for split_at in [8, 16, 20]:
    for mult39 in [1, 17]:
        for mult52 in [1, 6]:
            shell_m = shell.copy()
            shell_m[39] *= mult39
            shell_m[52] *= mult52

            pairs = []
            for i in range(32):
                div = 30 if i < split_at else 10
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if 0x77 in pairs:
                if check_key(pairs, f"split30_10_{split_at}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Brute force: modify 1 byte in best candidate
# ============================================================================
print("\n[3] Single byte modification on split div7/div10 base...")

for pos in range(32):
    for val in range(256):
        pairs = base.copy()
        pairs[pos] = val
        if check_key(pairs, f"mod_pos{pos}_val{val}"):
            exit()

print("  Single byte mod: no solution")

# ============================================================================
# Try 2-byte modifications at specific positions
# ============================================================================
print("\n[4] Two-byte modifications...")

# Key positions: 0 (first), 16 (has 0x77), 19 (had 0x77 in other config), 31 (last)
key_pos = [0, 16, 19, 31]

count = 0
for p1 in key_pos:
    for p2 in key_pos:
        if p1 >= p2:
            continue
        for v1 in range(256):
            for v2 in range(256):
                pairs = base.copy()
                pairs[p1] = v1
                pairs[p2] = v2
                if check_key(pairs, f"2byte_p{p1}v{v1}_p{p2}v{v2}"):
                    exit()
                count += 1
                if count % 100000 == 0:
                    print(f"  Checked {count} combinations...")

print(f"  Total 2-byte mods checked: {count}, no solution")

# ============================================================================
# Try completely different approach: pair rects based on digit sequence
# ============================================================================
print("\n[5] Pair rectangles using digit sequence as offset...")

digits = [0, 9, 1, 1, 1, 8, 1, 9, 1, 1, 1, 2, 2, 1, 1, 1]

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 30, 64]:
            pairs = []
            for i in range(32):
                offset = digits[i % 16]
                idx1 = i
                idx2 = (i + offset) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if pairs[0] == 0x28 or 0x77 in pairs:
                if check_key(pairs, f"digit_offset_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Try each digit as a per-byte divisor
# ============================================================================
print("\n[6] Each digit as a per-byte divisor (digit*10 or digit+1)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        # digit * 10 as divisor (0 becomes 10)
        pairs = []
        for i in range(32):
            digit = digits[i % 16]
            div = digit * 10 if digit > 0 else 10
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if 0x77 in pairs:
            if check_key(pairs, f"digit_times10_div_m{mult39}_{mult52}"):
                exit()

        # digit + 1 as divisor
        pairs = []
        for i in range(32):
            digit = digits[i % 16]
            div = digit + 1
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"digit_plus1_div_m{mult39}_{mult52}"):
            exit()

# ============================================================================
# What about the non-consecutive hint?
# Maybe pair rect i with rect (i + digit[i])
# ============================================================================
print("\n[7] Non-consecutive: rect i pairs with rect (i*2 + digit[i])...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        for div in [7, 10, 64]:
            pairs = []
            for i in range(32):
                digit = digits[i % 16]
                idx1 = i * 2
                idx2 = (i * 2 + digit) % 64
                val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                pairs.append(val)

            if 0x77 in pairs or pairs[0] == 0x28:
                if check_key(pairs, f"noncons_digit_div{div}_m{mult39}_{mult52}"):
                    exit()

# ============================================================================
# Maybe the FIX means to interpolate between the two divisors
# Position i uses: div = 30 - (30-10) * i / 31 = 30 - 20*i/31
# ============================================================================
print("\n[8] Interpolated divisor (30 to 10)...")

for mult39 in [1, 17]:
    for mult52 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult39
        shell_m[52] *= mult52

        pairs = []
        for i in range(32):
            # Linear interpolation from 30 to 10
            div = int(30 - 20 * i / 31)
            if div < 1:
                div = 1
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if 0x77 in pairs:
            if check_key(pairs, f"interp_div_m{mult39}_{mult52}"):
                exit()

print("\nFinal exploration complete.")
print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print("""
The puzzle remains unsolved. Key findings:

1. Digit sums: 30 + 10 = 40 = 0x28 (first byte with div7!)
2. shell[39] * 17 with div 7 gives 0x77 at position 19
3. Div 10 gives 0x77 at position 16
4. Split div7/div10 gives first byte 0x28 and 0x77 at pos 16

The missing piece is likely:
- The correct "following" (non-consecutive) pairing pattern
- The exact formula interpretation: -I *X+ LXIV /x/
- How lightning/skull symbols affect the computation
""")
