"""
Targeted approach: Find all ways to get 0x77 (119) and build around that.
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
KNOWN_BYTE = 119  # 0x77

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
    if len(byte_list) != 32 or KNOWN_BYTE not in byte_list:
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

# ============================================================================
# STEP 1: Find ALL (i,j) pairs and divisors that yield exactly 119
# ============================================================================
print("="*70)
print("Finding all ways to produce 0x77 (119)")
print("="*70)

shell = [r[2] for r in RECT_DATA]
shell_17 = shell.copy()
shell_17[39] *= 17
shell_6 = shell.copy()
shell_6[52] *= 6
shell_17_6 = shell.copy()
shell_17_6[39] *= 17
shell_17_6[52] *= 6

outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

area_sets = [
    ("shell", shell),
    ("shell_17", shell_17),
    ("shell_6", shell_6),
    ("shell_17_6", shell_17_6),
    ("outer", outer),
    ("inner", inner),
]

# For each area set, find pairs that produce 119
valid_119_combos = []

for area_name, areas in area_sets:
    for i in range(64):
        for j in range(i+1, 64):
            sum_val = areas[i] + areas[j]

            # Check various divisors
            for div in [1, 2, 4, 8, 16, 32, 64, 128, 256]:
                result = (sum_val // div) % 256
                if result == 119:
                    valid_119_combos.append({
                        'area': area_name,
                        'i': i, 'j': j,
                        'sum': sum_val,
                        'div': div,
                        'result': result
                    })

            # Also check (sum % 256 == 119)
            if sum_val % 256 == 119:
                valid_119_combos.append({
                    'area': area_name,
                    'i': i, 'j': j,
                    'sum': sum_val,
                    'div': 'mod256',
                    'result': sum_val % 256
                })

print(f"\nFound {len(valid_119_combos)} ways to produce 119")
print("\nTop candidates:")
for combo in valid_119_combos[:20]:
    print(f"  {combo['area']}: rect[{combo['i']}] + rect[{combo['j']}] = {combo['sum']} "
          f"// {combo['div']} = {combo['result']}")

# ============================================================================
# STEP 2: For each valid 119 combo, try to build a complete 32-byte key
# ============================================================================
print("\n" + "="*70)
print("Building complete keys around valid 119 combinations")
print("="*70)

# Focus on the most promising: shell_17_6 with div 64
best_combos = [c for c in valid_119_combos
               if c['area'] == 'shell_17_6' and c['div'] in [64, 128, 'mod256']]

print(f"\nFocusing on {len(best_combos)} shell_17_6 combinations")

for combo in best_combos[:10]:
    target_i, target_j = combo['i'], combo['j']
    div = 64 if combo['div'] == 'mod256' else combo['div']

    # Build a pairing where (target_i, target_j) appears at position k
    for target_pos in range(32):
        # Create pairing: consecutive for most, but insert target pair
        pairings = []
        used = {target_i, target_j}

        # First, place our known-good pair
        pairings.append((target_i, target_j))

        # Fill in remaining 31 pairs
        remaining = [x for x in range(64) if x not in used]

        # Try consecutive pairing of remaining
        for k in range(0, len(remaining)-1, 2):
            if len(pairings) < 32:
                pairings.append((remaining[k], remaining[k+1]))

        if len(pairings) == 32:
            # Rotate so target pair is at target_pos
            pairings = pairings[-(32-target_pos):] + pairings[:-(32-target_pos)]

            # Compute bytes
            bytes_list = []
            for i1, j1 in pairings:
                val = (shell_17_6[i1] + shell_17_6[j1]) // div
                bytes_list.append(val % 256)

            if check_key(bytes_list, f"built_from_{target_i}_{target_j}_pos{target_pos}"):
                exit()

# ============================================================================
# STEP 3: Try systematic pairing with constraint that 119 must appear
# ============================================================================
print("\n" + "="*70)
print("Systematic search with 119 constraint")
print("="*70)

areas = shell_17_6

# For divisor 64, find which consecutive pairs give what
consecutive_bytes = []
for i in range(32):
    val = (areas[i*2] + areas[i*2+1]) // 64
    consecutive_bytes.append(val % 256)

print(f"Consecutive bytes (div64): {consecutive_bytes}")
print(f"Contains 119: {119 in consecutive_bytes}")

if 119 in consecutive_bytes:
    print(f"  Position(s): {[i for i, v in enumerate(consecutive_bytes) if v == 119]}")

# Try different divisors
for div in [32, 48, 64, 80, 96, 128]:
    bytes_list = [(areas[i*2] + areas[i*2+1]) // div % 256 for i in range(32)]
    if 119 in bytes_list:
        print(f"\nDiv {div}: Contains 119 at position(s) {[i for i, v in enumerate(bytes_list) if v == 119]}")
        if check_key(bytes_list, f"consecutive_div{div}"):
            exit()

# ============================================================================
# STEP 4: Check if sum of sequence digits gives a clue
# ============================================================================
print("\n" + "="*70)
print("Sequence digit analysis")
print("="*70)

seq = [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1]
print(f"Sequence: {seq}")
print(f"Sum: {sum(seq)}")  # = 40
print(f"Sum * 17 = {sum(seq) * 17}")  # = 680
print(f"Sum * 6 = {sum(seq) * 6}")  # = 240

# Maybe 40 is the key divisor?
bytes_40 = [(areas[i*2] + areas[i*2+1]) // 40 % 256 for i in range(32)]
print(f"\nDiv 40 (sum of seq): {bytes_40}")
print(f"Contains 119: {119 in bytes_40}")
if check_key(bytes_40, "div40_sum_of_seq"):
    exit()

# Product of unique non-zero digits: 9*1*8*2 = 144
bytes_144 = [(areas[i*2] + areas[i*2+1]) // 144 % 256 for i in range(32)]
print(f"\nDiv 144: Contains 119: {119 in bytes_144}")
if check_key(bytes_144, "div144"):
    exit()

# ============================================================================
# STEP 5: Brute force divisors around expected range
# ============================================================================
print("\n" + "="*70)
print("Brute force divisor search")
print("="*70)

for div in range(20, 200):
    bytes_list = [(areas[i*2] + areas[i*2+1]) // div % 256 for i in range(32)]
    if 119 in bytes_list:
        if check_key(bytes_list, f"bf_div{div}"):
            exit()

# Try non-integer-like divisors using different formulas
for mult in range(1, 20):
    for div in range(20, 100):
        bytes_list = [((areas[i*2] + areas[i*2+1]) * mult) // div % 256 for i in range(32)]
        if 119 in bytes_list:
            if check_key(bytes_list, f"bf_mult{mult}_div{div}"):
                exit()

print("\nSearch complete. Key not found yet.")
print("\nMost promising avenue:")
print("  - shell_17_6 with correct pairing pattern")
print("  - The mini-puzzle encodes the pairing, not just the formula")
