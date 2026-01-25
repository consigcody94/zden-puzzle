"""
Deep exploration of affine transformations and combinations
that produced 119 (0x77)
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
    return False

def get_shell(mult40=17, mult53=6):
    shell = [r[2] for r in RECT_DATA]
    shell[39] *= mult40
    shell[52] *= mult53
    return shell

L, H, I, U = 12, 8, 9, 21
seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

print("="*70)
print("DEEP AFFINE EXPLORATION")
print("="*70)

# ============================================================================
# Affine with different divisors
# ============================================================================
print("\n[1] Affine with various divisors...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        for a in [U, L, H, I]:  # U=21 worked best
            for b in range(0, 25):
                for div in [32, 48, 64, 80, 96, 128]:
                    pairs = []
                    for i in range(32):
                        val = shell[i * 2] + shell[i * 2 + 1]
                        result = (a * val + b) // div % 256
                        pairs.append(result)

                    if check_key(pairs, f"affine_a{a}_b{b}_div{div}_m{mult40}_{mult53}"):
                        exit()

# ============================================================================
# Position-dependent affine
# ============================================================================
print("\n[2] Position-dependent affine (using sequence)...")

shell = get_shell(17, 6)

# Use sequence to vary 'a' or 'b' per position
for base_a in [U, L]:
    for base_div in [64, 128]:
        pairs = []
        for i in range(32):
            val = shell[i * 2] + shell[i * 2 + 1]
            s = seq[i % len(seq)]
            # a varies with sequence
            a = base_a + s
            result = (a * val) // base_div % 256
            pairs.append(result)

        if check_key(pairs, f"varA_base{base_a}_div{base_div}"):
            exit()

        # b varies with sequence
        pairs = []
        for i in range(32):
            val = shell[i * 2] + shell[i * 2 + 1]
            s = seq[i % len(seq)]
            result = (base_a * val + s * 10) // base_div % 256
            pairs.append(result)

        if check_key(pairs, f"varB_base{base_a}_div{base_div}"):
            exit()

# ============================================================================
# Transpose with affine
# ============================================================================
print("\n[3] Transposed with affine...")

shell = get_shell(17, 6)
# Transpose: read by columns
shell_T = []
for col in range(8):
    for row in range(8):
        shell_T.append(shell[row * 8 + col])

for a in [1, U, L]:
    for b in [0, U, L]:
        for div in [64, 128, 256]:
            pairs = []
            for i in range(32):
                val = shell_T[i * 2] + shell_T[i * 2 + 1]
                result = (a * val + b) // div % 256
                pairs.append(result)

            if check_key(pairs, f"transpose_a{a}_b{b}_div{div}"):
                exit()

# ============================================================================
# Combined operations
# ============================================================================
print("\n[4] Combined: XOR and affine...")

shell = get_shell(17, 6)

for shift in [4, 5, 6]:
    for a in [U, L]:
        for div in [1, 2, 4]:
            pairs = []
            for i in range(32):
                xor_val = (shell[i*2] >> shift) ^ (shell[i*2+1] >> shift)
                result = (a * xor_val) // div % 256
                pairs.append(result)

            if check_key(pairs, f"xor_shift{shift}_a{a}_div{div}"):
                exit()

# ============================================================================
# Using all LHIU in sequence
# ============================================================================
print("\n[5] LHIU in sequence...")

shell = get_shell(17, 6)
lhiu = [L, H, I, U]

for div in [32, 64, 128]:
    pairs = []
    for i in range(32):
        val = shell[i * 2] + shell[i * 2 + 1]
        # Cycle through L, H, I, U
        mult = lhiu[i % 4]
        result = (val * mult) // div % 256
        pairs.append(result)

    if check_key(pairs, f"lhiu_cycle_div{div}"):
        exit()

    # Different cycle: LHIU per 8 bytes
    pairs = []
    for i in range(32):
        val = shell[i * 2] + shell[i * 2 + 1]
        mult = lhiu[i // 8]
        result = (val * mult) // div % 256
        pairs.append(result)

    if check_key(pairs, f"lhiu_quarters_div{div}"):
        exit()

# ============================================================================
# Formula: |-I| * x / N + ... (from the symbols)
# ============================================================================
print("\n[6] Formula interpretation: |-I| xN+ /x?...")

# |-I| = Shell (already have)
# xN+ = multiply N, add something
# /x? = divide by x (unknown)

shell = get_shell(17, 6)

# N could be from sequence, /x? could be position-dependent
for N in [L, H, I, U]:
    for x_base in [L, H, I, U]:
        pairs = []
        for i in range(32):
            val = shell[i * 2] + shell[i * 2 + 1]
            s = seq[i % len(seq)]
            x = x_base + s if s > 0 else x_base
            if x == 0:
                x = 1
            result = (val * N + s) // x % 256
            pairs.append(result)

        if check_key(pairs, f"formula_N{N}_xbase{x_base}"):
            exit()

# ============================================================================
# Byte reversal and endianness
# ============================================================================
print("\n[7] Byte reversal patterns...")

shell = get_shell(17, 6)

# Best candidates reversed
for div in [64, 128]:
    pairs = [(shell[i*2] + shell[i*2+1]) // div % 256 for i in range(32)]

    # Reverse pairs
    pairs_rev = pairs[::-1]
    if check_key(pairs_rev, f"reversed_div{div}"):
        exit()

    # Reverse each 4 bytes
    pairs_4rev = []
    for chunk in range(8):
        pairs_4rev.extend(pairs[chunk*4:(chunk+1)*4][::-1])
    if check_key(pairs_4rev, f"4byte_rev_div{div}"):
        exit()

    # Reverse each 8 bytes
    pairs_8rev = []
    for chunk in range(4):
        pairs_8rev.extend(pairs[chunk*8:(chunk+1)*8][::-1])
    if check_key(pairs_8rev, f"8byte_rev_div{div}"):
        exit()

    # Swap adjacent bytes
    pairs_swap = []
    for i in range(0, 32, 2):
        pairs_swap.append(pairs[i+1] if i+1 < 32 else pairs[i])
        pairs_swap.append(pairs[i])
    if check_key(pairs_swap[:32], f"adjacent_swap_div{div}"):
        exit()

# ============================================================================
# Modular inverse (Hill cipher decryption uses this)
# ============================================================================
print("\n[8] Modular operations...")

def mod_inverse(a, m):
    """Extended Euclidean Algorithm for modular inverse"""
    if a < 0:
        a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        return None
    return x % m

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y

shell = get_shell(17, 6)

# Apply modular inverse if it exists
for mod in [251, 256]:  # 251 is prime
    for div in [64, 128]:
        pairs = []
        for i in range(32):
            val = (shell[i*2] + shell[i*2+1]) // div
            inv = mod_inverse(val, mod) if val > 0 else 0
            pairs.append(inv if inv else val % 256)

        pairs = [p % 256 for p in pairs]
        if check_key(pairs, f"mod_inverse_mod{mod}_div{div}"):
            exit()

print("\nDeep affine exploration complete.")
print("Continuing with more approaches...")
