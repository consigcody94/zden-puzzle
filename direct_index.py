"""
Maybe 09111819 and 11122111 directly tell us which rectangles to use.
Let's interpret them as indices into the 64 rectangles.
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
            return True
    return False

print("="*70)
print("DIRECT INDEX INTERPRETATION")
print("="*70)

# Interpretations of 09111819 11122111
# Reading as pairs of digits: 09-11-18-19 and 11-12-21-11
pairs_before = [(0, 9), (1, 1), (1, 8), (1, 9)]
pairs_after = [(1, 1), (1, 2), (2, 1), (1, 1)]

# Or as single digits for 32 bytes
single_digits = [0, 9, 1, 1, 1, 8, 1, 9, 1, 1, 1, 2, 2, 1, 1, 1]

# Or as different groupings
# 0-9-11-18-19 and 11-12-21-11
indices_v1 = [0, 9, 11, 18, 19, 11, 12, 21, 11]

# ============================================================================
# Test 1: Use sequence digits as direct rect indices
# ============================================================================
print("\n[1] Sequence as direct rectangle indices...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [1, 7, 64, 127]:
            # Use single digits repeated to fill 64 positions
            idx_pattern = (single_digits * 4)[:64]

            # Pair consecutive pattern values
            pairs = []
            for i in range(32):
                idx1 = idx_pattern[i * 2] % 64
                idx2 = idx_pattern[i * 2 + 1] % 64
                val = (shell_m[idx1] + shell_m[idx2]) // max(div, 1) % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"direct_idx_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 2: Traverse grid using sequence as moves
# ============================================================================
print("\n[2] Grid traversal using sequence as moves...")

def grid_to_idx(row, col):
    return (row % 8) * 8 + (col % 8)

# Moves: 0=stay, 1=right, 2=down, 8=next_row, 9=diag_down_right
move_map = {
    0: (0, 0),
    1: (0, 1),
    2: (0, 2),
    8: (1, 0),
    9: (1, 1),
}

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [1, 7, 64]:
            row, col = 0, 0
            visited = []
            for move in (single_digits * 4)[:64]:
                dr, dc = move_map.get(move, (0, 1))
                row = (row + dr) % 8
                col = (col + dc) % 8
                visited.append(grid_to_idx(row, col))

            # Pair the visited indices
            pairs = []
            for i in range(32):
                idx1 = visited[i * 2] if i * 2 < len(visited) else 0
                idx2 = visited[i * 2 + 1] if i * 2 + 1 < len(visited) else 0
                val = (shell_m[idx1] + shell_m[idx2]) // max(div, 1) % 256
                pairs.append(val)

            if 119 in pairs:
                if check_key(pairs, f"traverse_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 3: Use 09, 11, 18, 19 as key positions
# ============================================================================
print("\n[3] Two-digit numbers as positions...")

# 09, 11, 18, 19 from first sequence
# 11, 12, 21, 11 from second sequence
key_positions = [9, 11, 18, 19, 11, 12, 21, 11]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Base calculation
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Apply special treatment to key positions
            pairs = base.copy()
            for pos in key_positions:
                if pos < 32:
                    pairs[pos] = 119

            if check_key(pairs, f"key_pos_77_div{div}_m{mult40}_{mult53}"):
                exit()

            # Or swap bytes at those positions
            pairs = base.copy()
            for i in range(len(key_positions) - 1):
                p1, p2 = key_positions[i], key_positions[i + 1]
                if p1 < 32 and p2 < 32:
                    pairs[p1], pairs[p2] = pairs[p2], pairs[p1]

            if check_key(pairs, f"key_pos_swap_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Test 4: FIX as rotation or shift
# ============================================================================
print("\n[4] FIX as rotation operation...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            base = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]

            # Rotate left/right by various amounts
            for rot in range(1, 32):
                rotated = base[rot:] + base[:rot]
                if check_key(rotated, f"rot_left{rot}_div{div}_m{mult40}_{mult53}"):
                    exit()

# ============================================================================
# Test 5: Random sampling (brute force a bit)
# ============================================================================
print("\n[5] Testing additional random patterns...")

import random
random.seed(42)  # Reproducible

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [7, 64, 127]:
            # Try some random pairings
            for attempt in range(100):
                indices = list(range(64))
                random.shuffle(indices)

                pairs = []
                for i in range(32):
                    idx1 = indices[i * 2]
                    idx2 = indices[i * 2 + 1]
                    val = (shell_m[idx1] + shell_m[idx2]) // div % 256
                    pairs.append(val)

                if 119 in pairs:
                    if check_key(pairs, f"random_{attempt}_div{div}_m{mult40}_{mult53}"):
                        exit()

print("\nDirect index search complete.")
print("\n" + "="*70)
print("SUMMARY")
print("="*70)
print("""
This puzzle requires finding the exact interpretation of:
- 09111819 FIX 11122111
- Formula: -I *X+ LXIV /x/
- Lightning bolt and skull symbols
- The 'not consecutive' pairing hint

Key findings so far:
- Divisor 7 with mult17 gives 119 at position 19
- Divisor 127 with mult17 also gives 119 at position 19
- 17 * 7 = 119
- 839 / 118 = 7 (ratio of special rect shells)
- LXIV = 64 (Roman numeral)

The solution likely requires the correct combination of:
1. The right pairing/ordering pattern
2. The right arithmetic operation (div 7, 64, or 127?)
3. Possibly XOR or other bit operations (lightning symbol)
4. Possibly subtraction (skull symbol)
""")
