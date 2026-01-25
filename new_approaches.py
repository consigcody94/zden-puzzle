"""
Fresh approaches to crack Zden Level 5:
1. Bitcoin transaction data as hints
2. Different number bases
3. Strikethrough = subtraction
4. XOR/AND/OR operations
5. Permutation encoding
6. The formula symbols as literal operations
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

# Bitcoin transaction amounts (satoshis)
BTC_AMOUNTS = [260414, 88248, 1338, 205550]  # Total: 555550

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"
KNOWN_BYTE = 119

def privkey_to_address(privkey_hex, compressed=True):
    try:
        privkey_bytes = bytes.fromhex(privkey_hex)
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
    privkey_hex = ''.join(f'{b:02x}' for b in byte_list)
    addr_c = privkey_to_address(privkey_hex, True)
    addr_u = privkey_to_address(privkey_hex, False)
    if addr_c == TARGET or addr_u == TARGET:
        print(f"\n{'='*60}")
        print(f"SOLVED! {desc}")
        print(f"Key: {privkey_hex}")
        print(f"{'='*60}")
        return True
    if KNOWN_BYTE in byte_list:
        # Track promising candidates
        pass
    return False

def get_shell(mult40=17, mult53=6):
    shell = [r[2] for r in RECT_DATA]
    shell[39] *= mult40
    shell[52] *= mult53
    return shell

print("="*70)
print("NEW APPROACHES")
print("="*70)

# ============================================================================
# APPROACH 1: Bitcoin amounts as divisors or multipliers
# ============================================================================
print("\n[1] Bitcoin transaction amounts as parameters...")

shell = get_shell(17, 6)

# Try BTC amounts as divisors
for amt in BTC_AMOUNTS + [sum(BTC_AMOUNTS)]:
    for sub_div in [1, 10, 100, 1000]:
        div = amt // sub_div
        if div > 0 and div < 10000:
            pairs = [(shell[i*2] + shell[i*2+1]) // div % 256 for i in range(32)]
            if check_key(pairs, f"btc_amt_{amt}_subdiv{sub_div}"):
                exit()

# 555550 / 64 = 8680.46... try 8680
pairs = [(shell[i*2] + shell[i*2+1]) // 8680 % 256 for i in range(32)]
if 119 in pairs:
    print(f"  555550/64=8680: Contains 119")
    check_key(pairs, "btc_555550_div64")

# ============================================================================
# APPROACH 2: Strikethrough means SUBTRACTION not addition
# ============================================================================
print("\n[2] Strikethrough = subtraction (not consecutive = difference)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        for div in [1, 8, 16, 32, 64]:
            # Subtraction instead of addition
            pairs = [abs(shell[i*2] - shell[i*2+1]) // div % 256 for i in range(32)]
            if 119 in pairs:
                print(f"  m{mult40}_{mult53} div{div}: Contains 119 (subtraction)")
                if check_key(pairs, f"subtract_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# APPROACH 3: XOR instead of arithmetic
# ============================================================================
print("\n[3] XOR operations...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        # XOR pairs
        pairs = [(shell[i*2] ^ shell[i*2+1]) % 256 for i in range(32)]
        if 119 in pairs:
            print(f"  m{mult40}_{mult53} XOR: Contains 119")
            if check_key(pairs, f"xor_m{mult40}_{mult53}"):
                exit()

        # XOR with shift
        for shift in [4, 8, 12]:
            pairs = [((shell[i*2] >> shift) ^ (shell[i*2+1] >> shift)) % 256 for i in range(32)]
            if 119 in pairs:
                print(f"  m{mult40}_{mult53} XOR shift{shift}: Contains 119")
                if check_key(pairs, f"xor_shift{shift}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# APPROACH 4: Numbers in different bases
# ============================================================================
print("\n[4] Mini-puzzle numbers in different bases...")

# 09111819 in base 10 = 9111819
# What if it's octal? 09111819 is invalid octal (has 8,9)
# What if digits are separate base-10 values that map to base-something?

# Try: treat as base-12 (duodecimal) where 0-9, A=10, B=11
# 09111819 in base 12 = 0*12^7 + 9*12^6 + 1*12^5 + 1*12^4 + 1*12^3 + 8*12^2 + 1*12 + 9
num_base12 = 0*12**7 + 9*12**6 + 1*12**5 + 1*12**4 + 1*12**3 + 8*12**2 + 1*12 + 9
print(f"  09111819 as base-12: {num_base12}")

# Try as divisor
shell = get_shell(17, 6)
if num_base12 > 0:
    for sub in [1, 100, 1000, 10000, 100000]:
        d = num_base12 // sub
        if 0 < d < 10000:
            pairs = [(shell[i*2] + shell[i*2+1]) // d % 256 for i in range(32)]
            if 119 in pairs:
                print(f"    base12/{sub}={d}: Contains 119")
                check_key(pairs, f"base12_div{d}")

# ============================================================================
# APPROACH 5: The formula |-I xN+ LHIU /x? as literal operations
# ============================================================================
print("\n[5] Formula as literal sequence of operations...")

# |-I| = absolute(Outer - Inner) = Shell (already using this)
# xN+ = multiply by N, add (N from LHIU = L=12, H=8, I=9, U=21)
# /x? = divide by x (unknown)

# Try: Shell * 12 + 8 / 9 / 21 or variations
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]
shell = [abs(o - i) for o, i in zip(outer, inner)]
shell[39] *= 17
shell[52] *= 6

# Formula: |O-I| * L + H, then /I, then something with U
L, H, I, U = 12, 8, 9, 21

for op_order in itertools.permutations([L, H, I, U]):
    a, b, c, d = op_order
    pairs = []
    for i in range(32):
        val = shell[i*2] + shell[i*2+1]
        # Try: ((val * a + b) / c) % d or variations
        try:
            result = ((val * a + b) // c) % 256
            pairs.append(result)
        except:
            pairs.append(0)

    if len(pairs) == 32 and 119 in pairs:
        print(f"  Formula order {op_order}: Contains 119")
        if check_key(pairs, f"formula_{op_order}"):
            exit()

# ============================================================================
# APPROACH 6: Digits encode a permutation
# ============================================================================
print("\n[6] Digits as permutation indices...")

# 0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1 could index into the rectangles
# But there are repeats... maybe they specify row permutation?

digits = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
shell = get_shell(17, 6)

# Permute rows based on digits
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        # Use digit to pick which row to read from
        d = digits[i % len(digits)]
        row = d % 8
        col = i % 8
        idx1 = row * 8 + col
        idx2 = ((d + 1) % 8) * 8 + (col + 1) % 8
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    if 119 in pairs:
        print(f"  Permutation div{div}: Contains 119")
        if check_key(pairs, f"permute_div{div}"):
            exit()

# ============================================================================
# APPROACH 7: Read rectangles in order specified by mini-puzzle
# ============================================================================
print("\n[7] Rectangle reading order from mini-puzzle...")

# 09, 11, 18, 19, 11, 12, 21, 11 as rectangle indices
indices_2digit = [9, 11, 18, 19, 11, 12, 21, 11]
# Extended to 64 indices
indices_ext = []
for i in range(64):
    indices_ext.append(indices_2digit[i % len(indices_2digit)] + (i // 8) * 8)
indices_ext = [i % 64 for i in indices_ext]

shell = get_shell(17, 6)
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1 = indices_ext[i * 2]
        idx2 = indices_ext[i * 2 + 1]
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    if 119 in pairs:
        print(f"  Reading order div{div}: Contains 119")
        if check_key(pairs, f"read_order_div{div}"):
            exit()

# ============================================================================
# APPROACH 8: Use ONLY the shell values that equal specific patterns
# ============================================================================
print("\n[8] Shell value patterns...")

shell = get_shell(17, 6)

# Find shells divisible by specific numbers
for magic in [17, 6, 64, 119]:
    divisible = [i for i, s in enumerate(shell) if s % magic == 0]
    print(f"  Shells divisible by {magic}: {len(divisible)} rectangles")

# ============================================================================
# APPROACH 9: Interleave based on FIN separator
# ============================================================================
print("\n[9] FIN as interleave marker...")

seq1 = [0,9,1,1,1,8,1,9]  # Before FIN
seq2 = [1,1,1,2,2,1,1,1]  # After FIN

shell = get_shell(17, 6)

# Interleave: alternate between seq1 and seq2 interpretations
for div in [16, 32, 64]:
    pairs = []
    for i in range(32):
        idx1 = i * 2
        # Alternate sequences
        if i % 2 == 0:
            offset = seq1[i // 2 % len(seq1)]
        else:
            offset = seq2[i // 2 % len(seq2)]
        idx2 = (idx1 + 1 + offset) % 64
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    if 119 in pairs:
        print(f"  Interleave div{div}: Contains 119")
        if check_key(pairs, f"interleave_div{div}"):
            exit()

# ============================================================================
# APPROACH 10: Product instead of sum
# ============================================================================
print("\n[10] Product instead of sum...")

shell = get_shell(17, 6)

for div in [1000, 10000, 100000, 1000000]:
    pairs = [(shell[i*2] * shell[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        print(f"  Product div{div}: Contains 119")
        if check_key(pairs, f"product_div{div}"):
            exit()

# ============================================================================
# APPROACH 11: Average instead of sum
# ============================================================================
print("\n[11] Average instead of sum...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        for div in [8, 16, 32]:
            pairs = [((shell[i*2] + shell[i*2+1]) // 2) // div % 256 for i in range(32)]
            if 119 in pairs:
                print(f"  Average m{mult40}_{mult53} div{div}: Contains 119")
                if check_key(pairs, f"average_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# APPROACH 12: Modular with different moduli per position
# ============================================================================
print("\n[12] Position-dependent modulus...")

shell = get_shell(17, 6)
seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

for base_div in [32, 64]:
    pairs = []
    for i in range(32):
        val = (shell[i*2] + shell[i*2+1]) // base_div
        mod = 256 - seq[i % len(seq)]  # Variable modulus based on sequence
        pairs.append(val % mod if mod > 0 else val % 256)

    if 119 in pairs:
        print(f"  Variable mod div{base_div}: Contains 119")
        if check_key(pairs, f"varmod_div{base_div}"):
            exit()

print("\nNew approaches exploration complete.")
