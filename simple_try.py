"""
Ultra-simple approaches that might have been overlooked.
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

def count_match(addr):
    if not addr:
        return 0
    return sum(1 for a, b in zip(addr, TARGET) if a == b)

print("="*70)
print("SIMPLE APPROACHES")
print("="*70)

# ============================================================================
# 1. Hex representation of values
# ============================================================================
print("\n[1] Hex representations...")

# Shell values in hex, take digits
hex_str = ''.join(f'{s:04x}' for s in shell[:32])
print(f"Shell hex (first 32): {hex_str[:64]}...")

# Take every 2 chars as a byte
key = [int(hex_str[i:i+2], 16) for i in range(0, 64, 2)]
addr = privkey_to_address(bytes(key), True)
print(f"  Hex bytes: {addr}, match: {count_match(addr)}")
if check_key(key, "hex_bytes"):
    exit()

# ============================================================================
# 2. High and low bytes of shell values
# ============================================================================
print("\n[2] High/low bytes...")

# Low bytes (mod 256)
key = [s % 256 for s in shell[:32]]
addr = privkey_to_address(bytes(key), True)
print(f"  Low bytes: {addr}, match: {count_match(addr)}")
if check_key(key, "low_bytes"):
    exit()

# High bytes (div 256)
key = [s // 256 for s in shell[:32]]
addr = privkey_to_address(bytes(key), True)
print(f"  High bytes: {addr}, match: {count_match(addr)}")
if check_key(key, "high_bytes"):
    exit()

# ============================================================================
# 3. Simply divide by various numbers
# ============================================================================
print("\n[3] Simple divisions...")

for div in list(range(1, 100)) + [100, 200, 256, 512, 1000]:
    key = [s // div % 256 for s in shell[:32]]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 4:
        print(f"  div {div}: {match} chars - {addr[:10]}...")
    if check_key(key, f"simple_div_{div}"):
        exit()

# ============================================================================
# 4. Average of all three components
# ============================================================================
print("\n[4] Average of outer+inner+shell...")

for div in [3, 10, 21, 30]:
    key = []
    for i in range(32):
        avg = (outer[i] + inner[i] + shell[i]) // div % 256
        key.append(avg)

    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  avg div{div}: {match} chars - {addr[:10]}...")
    if check_key(key, f"avg_div{div}"):
        exit()

# ============================================================================
# 5. Differences: outer - shell (= inner), inner - shell, etc.
# ============================================================================
print("\n[5] Differences...")

for div in [7, 10, 17]:
    # inner = outer - shell, so outer - shell = inner
    key = [(outer[i] - shell[i]) // div % 256 for i in range(32)]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  (O-S) div{div}: {match} chars")
    if check_key(key, f"outer_minus_shell_div{div}"):
        exit()

# ============================================================================
# 6. Ratios
# ============================================================================
print("\n[6] Ratios...")

key = [int(outer[i] / inner[i] * 100) % 256 if inner[i] > 0 else 0 for i in range(32)]
addr = privkey_to_address(bytes(key), True)
print(f"  O/I*100: {addr}, match: {count_match(addr)}")
if check_key(key, "ratio_oi"):
    exit()

key = [int(shell[i] / outer[i] * 100) % 256 if outer[i] > 0 else 0 for i in range(32)]
addr = privkey_to_address(bytes(key), True)
print(f"  S/O*100: {addr}, match: {count_match(addr)}")
if check_key(key, "ratio_so"):
    exit()

# ============================================================================
# 7. Sum of digits of shell values
# ============================================================================
print("\n[7] Digit sums...")

def digit_sum(n):
    return sum(int(d) for d in str(n))

key = [digit_sum(s) for s in shell[:32]]
print(f"  Digit sums: {key}")
# Pad to valid byte range
key = [k % 256 for k in key]
addr = privkey_to_address(bytes(key), True)
print(f"  Address: {addr}, match: {count_match(addr)}")
if check_key(key, "digit_sum"):
    exit()

# ============================================================================
# 8. Last 2 digits of shell values
# ============================================================================
print("\n[8] Last 2 digits...")

key = [s % 100 for s in shell[:32]]
addr = privkey_to_address(bytes(key), True)
print(f"  Last 2 digits: {addr}, match: {count_match(addr)}")
if check_key(key, "last2digits"):
    exit()

# First 2 digits
key = [int(str(s)[:2]) if s >= 100 else s for s in shell[:32]]
addr = privkey_to_address(bytes(key), True)
print(f"  First 2 digits: {addr}, match: {count_match(addr)}")
if check_key(key, "first2digits"):
    exit()

# ============================================================================
# 9. Using the indices 39 and 57 more directly
# ============================================================================
print("\n[9] Special indices 39 and 57...")

# What if bytes 0 and 19 come from these, rest normal?
for formula in ['add', 'sub']:
    for div in [7, 10]:
        key = []
        for i in range(32):
            if formula == 'add':
                val = (shell[i*2] + shell[i*2+1]) // div % 256
            else:
                val = abs(shell[i*2] - shell[i*2+1]) // div % 256
            key.append(val)

        # Override byte 0 with shell[57]/7
        key[0] = shell[57] // 7

        # Try different positions for shell[39]/7
        for pos in range(1, 32):
            key_test = key.copy()
            key_test[pos] = shell[39] // 7

            if check_key(key_test, f"override_{formula}_{div}_{pos}"):
                exit()

# ============================================================================
# 10. The "crypto" word encoded
# ============================================================================
print("\n[10] Crypto-based encoding...")

# "GeCRiTz" appears in target - letters?
# G=7, e=5, C=3, R=18, i=9, T=20, z=26
gecritz = [7, 5, 3, 18, 9, 20, 26]

# Try using these as divisors for specific positions
for start in range(26):
    key = shell[:32].copy()
    for i, div in enumerate(gecritz):
        if start + i < 32 and div > 0:
            key[start + i] = shell[start + i] // div % 256

    if check_key(key, f"gecritz_at_{start}"):
        exit()

# ============================================================================
# 11. Binary operations
# ============================================================================
print("\n[11] Binary operations...")

# AND with various masks
for mask in [0x7F, 0x3F, 0xF0, 0x0F]:
    key = [s & mask for s in shell[:32]]
    addr = privkey_to_address(bytes(key), True)
    match = count_match(addr)
    if match >= 3:
        print(f"  AND {hex(mask)}: {match} chars")
    if check_key(key, f"and_{hex(mask)}"):
        exit()

# ============================================================================
# 12. Systematic pair formula search
# ============================================================================
print("\n[12] Systematic pair formulas...")

best = 0
for a in range(-2, 3):
    for b in range(-2, 3):
        if a == 0 and b == 0:
            continue
        for div in range(1, 50):
            key = []
            for i in range(32):
                val = (a * shell[i*2] + b * shell[i*2+1]) // div
                if val < 0:
                    val = abs(val)
                key.append(val % 256)

            addr = privkey_to_address(bytes(key), True)
            match = count_match(addr)
            if match > best:
                best = match
                print(f"  {a}*s0 + {b}*s1 / {div}: {match} chars - {addr[:10]}...")

            if check_key(key, f"linear_{a}_{b}_{div}"):
                exit()

print(f"\nBest linear: {best}")

# ============================================================================
# 13. Hash-based approaches
# ============================================================================
print("\n[13] Hash-based...")

# SHA256 of shell values concatenated
shell_bytes = b''.join(s.to_bytes(2, 'big') for s in shell)
key = list(hashlib.sha256(shell_bytes).digest())
addr = privkey_to_address(bytes(key), True)
print(f"  SHA256 of shell: {addr}, match: {count_match(addr)}")
if check_key(key, "sha256_shell"):
    exit()

# MD5 doubled
md5 = hashlib.md5(shell_bytes).digest()
key = list(md5 + md5)
addr = privkey_to_address(bytes(key), True)
print(f"  MD5 doubled: {addr}, match: {count_match(addr)}")
if check_key(key, "md5_doubled"):
    exit()

print("\n" + "="*70)
print("Simple approaches complete")
print("="*70)
