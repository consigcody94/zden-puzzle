"""
Deep exploration of XOR and Formula approaches that produced 119
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
    return False

def get_shell(mult40=17, mult53=6):
    shell = [r[2] for r in RECT_DATA]
    shell[39] *= mult40
    shell[52] *= mult53
    return shell

print("="*70)
print("DEEP XOR EXPLORATION")
print("="*70)

# XOR with various shifts and combinations
for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell = get_shell(mult40, mult53)

        # XOR with different shifts
        for shift in range(1, 16):
            pairs = [((shell[i*2] >> shift) ^ (shell[i*2+1] >> shift)) % 256 for i in range(32)]
            if check_key(pairs, f"xor_shift{shift}_m{mult40}_{mult53}"):
                exit()

        # XOR then apply operations
        for shift in [4, 5, 6]:
            for xor_const in [0, 119, 0x77, 64, 17, 6]:
                pairs = [(((shell[i*2] >> shift) ^ (shell[i*2+1] >> shift)) ^ xor_const) % 256 for i in range(32)]
                if check_key(pairs, f"xor_shift{shift}_xorconst{xor_const}_m{mult40}_{mult53}"):
                    exit()

        # Sum then XOR with constant
        for div in [32, 64, 128]:
            for xor_const in [0x77, 64, 17, 6, 23]:
                pairs = [((shell[i*2] + shell[i*2+1]) // div ^ xor_const) % 256 for i in range(32)]
                if check_key(pairs, f"sum_div{div}_xor{xor_const}_m{mult40}_{mult53}"):
                    exit()

print("\n" + "="*70)
print("DEEP FORMULA EXPLORATION")
print("="*70)

# LHIU = 12, 8, 9, 21
L, H, I, U = 12, 8, 9, 21

shell = get_shell(17, 6)

# More formula variations
for a in [L, H, I, U, 1]:
    for b in [L, H, I, U, 0]:
        for c in [L, H, I, U, 1]:
            if c == 0:
                continue
            for d in [64, 128, 256, L*H, H*I, I*U]:
                if d == 0:
                    continue

                pairs = []
                for i in range(32):
                    val = shell[i*2] + shell[i*2+1]
                    result = ((val * a + b) // c) % d
                    pairs.append(result % 256)

                if 119 in pairs and check_key(pairs, f"formula_a{a}_b{b}_c{c}_d{d}"):
                    exit()

# Try formula with sequence integration
seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]

for base_mult in [1, L, H, I, U]:
    for base_div in [L, H, I, U, L*H, H*I]:
        if base_div == 0:
            continue
        pairs = []
        for i in range(32):
            val = shell[i*2] + shell[i*2+1]
            s = seq[i % len(seq)]
            if s == 0:
                s = 1
            result = (val * base_mult * s) // base_div
            pairs.append(result % 256)

        if 119 in pairs and check_key(pairs, f"formula_seq_mult{base_mult}_div{base_div}"):
            exit()

print("\n" + "="*70)
print("COMBINED APPROACHES")
print("="*70)

# Combine XOR and formula
shell = get_shell(17, 6)

for shift in [3, 4, 5, 6]:
    for formula_div in [L, H, I, U, L*H]:
        if formula_div == 0:
            continue

        # XOR then divide
        pairs = [(((shell[i*2] >> shift) ^ (shell[i*2+1] >> shift)) * L) // formula_div % 256 for i in range(32)]
        if check_key(pairs, f"xor_shift{shift}_times{L}_div{formula_div}"):
            exit()

        # Divide then XOR
        pairs = [((shell[i*2] // formula_div) ^ (shell[i*2+1] // formula_div)) % 256 for i in range(32)]
        if check_key(pairs, f"div{formula_div}_then_xor"):
            exit()

print("\n" + "="*70)
print("SEQUENCE-BASED OPERATIONS")
print("="*70)

# Use sequence values as operation selectors
# 0 = add, 1 = subtract, 2 = xor, 8 = multiply, 9 = special
shell = get_shell(17, 6)

for div in [32, 64, 128]:
    pairs = []
    for i in range(32):
        op = seq[i % len(seq)]
        v1, v2 = shell[i*2], shell[i*2+1]

        if op == 0:
            val = v1 + v2
        elif op == 1:
            val = abs(v1 - v2)
        elif op == 2:
            val = v1 ^ v2
        elif op == 8:
            val = (v1 * v2) // 1000
        elif op == 9:
            val = (v1 + v2) * 2
        else:
            val = v1 + v2

        pairs.append((val // div) % 256)

    if check_key(pairs, f"op_select_div{div}"):
        exit()

print("\n" + "="*70)
print("NON-CONSECUTIVE SPECIFIC PATTERNS")
print("="*70)

# "Following" but not "consecutive" could mean:
# - Every other (skip 1)
# - Diagonal neighbors
# - Same column different row

shell = get_shell(17, 6)

# Skip patterns
for skip in range(2, 8):
    for div in [32, 64]:
        pairs = []
        for i in range(32):
            idx1 = (i * 2) % 64
            idx2 = (i * 2 + skip) % 64
            val = (shell[idx1] + shell[idx2]) // div
            pairs.append(val % 256)

        if check_key(pairs, f"skip{skip}_div{div}"):
            exit()

# Diagonal neighbors in 8x8 grid
for div in [32, 64]:
    pairs = []
    for i in range(32):
        row = (i * 2) // 8
        col = (i * 2) % 8
        idx1 = row * 8 + col
        # Diagonal neighbor
        idx2 = ((row + 1) % 8) * 8 + ((col + 1) % 8)
        val = (shell[idx1] + shell[idx2]) // div
        pairs.append(val % 256)

    if check_key(pairs, f"diagonal_div{div}"):
        exit()

# Same column, different rows
for row_skip in [2, 3, 4]:
    for div in [32, 64]:
        pairs = []
        for i in range(32):
            col = i % 8
            row1 = (i // 8) * 2
            row2 = row1 + row_skip
            idx1 = (row1 % 8) * 8 + col
            idx2 = (row2 % 8) * 8 + col
            val = (shell[idx1] + shell[idx2]) // div
            pairs.append(val % 256)

        if check_key(pairs, f"samecol_rowskip{row_skip}_div{div}"):
            exit()

print("\n" + "="*70)
print("BYTE POSITION EXPLORATION")
print("="*70)

# Maybe 119 should be at a specific position based on hint
shell = get_shell(17, 6)

# Find positions where 119 naturally appears with different configs
for div in range(20, 100):
    pairs = [(shell[i*2] + shell[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        positions = [i for i, v in enumerate(pairs) if v == 119]
        # Check if position relates to sequence
        seq_vals_at_pos = [seq[p % len(seq)] for p in positions]
        print(f"  Div {div}: 119 at {positions}, seq vals: {seq_vals_at_pos}")
        check_key(pairs, f"div{div}")

print("\nDeep exploration complete.")
