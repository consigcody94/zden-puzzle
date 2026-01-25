"""
Creative approaches - thinking outside the box
"""
import hashlib
import ecdsa
import base58
import struct

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
            print(f"{'='*60}")
            return True
    return False

print("="*70)
print("CREATIVE APPROACHES")
print("="*70)

# ============================================================================
# Approach 1: Maybe we need to use 64 bytes (one per rect), then hash
# ============================================================================
print("\n[1] 64 bytes hashed to 32...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [8, 16, 32, 64]:
            # One byte per rectangle
            bytes_64 = [s // div % 256 for s in shell_m]

            # SHA256 hash
            hash_result = hashlib.sha256(bytes(bytes_64)).digest()
            if check_key(list(hash_result), f"sha256_64b_m{mult40}_{mult53}_div{div}"):
                exit()

            # Take every other byte
            pairs = bytes_64[::2]
            if check_key(pairs, f"every_other_m{mult40}_{mult53}_div{div}"):
                exit()

# ============================================================================
# Approach 2: Maybe it's row-based (8x8 grid)
# ============================================================================
print("\n[2] Row-based sums...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [128, 256, 512]:
            # Sum each row of 8
            row_sums = [sum(shell_m[i*8:(i+1)*8]) for i in range(8)]

            # Each row sum becomes 4 bytes
            pairs = []
            for rs in row_sums:
                pairs.append((rs >> 24) % 256)
                pairs.append((rs >> 16) % 256)
                pairs.append((rs >> 8) % 256)
                pairs.append(rs % 256)

            if len(pairs) >= 32:
                if check_key(pairs[:32], f"row_sums_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 3: Binary representation of areas
# ============================================================================
print("\n[3] Binary encoding of areas...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        # Treat each shell as binary (above/below threshold)
        for threshold in [500, 1000, 1500]:
            bits = [1 if s > threshold else 0 for s in shell_m]
            # Pack 8 bits into bytes
            pairs = []
            for i in range(8):
                byte_val = 0
                for j in range(8):
                    byte_val = (byte_val << 1) | bits[i*8 + j]
                pairs.append(byte_val)

            # Need 32 bytes, so we need more bits
            # Use outer, inner, shell all together
            all_bits = []
            for s in shell_m:
                all_bits.append(1 if s > threshold else 0)
            for o in outer:
                all_bits.append(1 if o > threshold * 4 else 0)
            for i in inner:
                all_bits.append(1 if i > threshold * 2 else 0)

            pairs = []
            for i in range(32):
                byte_val = 0
                for j in range(8):
                    if i*8 + j < len(all_bits):
                        byte_val = (byte_val << 1) | all_bits[i*8 + j]
                pairs.append(byte_val)

            if check_key(pairs, f"binary_thresh{threshold}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Approach 4: GCD/LCM operations
# ============================================================================
print("\n[4] GCD-based operations...")

import math

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        pairs = []
        for i in range(32):
            g = math.gcd(shell_m[i*2], shell_m[i*2+1])
            pairs.append(g % 256)

        if 119 in pairs:
            if check_key(pairs, f"gcd_m{mult40}_{mult53}"):
                exit()

        # GCD divided by something
        for div in [1, 2, 4, 8]:
            pairs = [math.gcd(shell_m[i*2], shell_m[i*2+1]) // div % 256 for i in range(32)]
            if check_key(pairs, f"gcd_div{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Approach 5: Modular arithmetic with special primes
# ============================================================================
print("\n[5] Modular arithmetic...")

primes = [17, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157]

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for prime in [119, 127, 131, 137]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) % prime for i in range(32)]
            if check_key(pairs, f"mod{prime}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Approach 6: Use position indices more creatively
# ============================================================================
print("\n[6] Position-weighted values...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64, 128]:
            # Multiply by position
            pairs = [(shell_m[i*2] * (i+1) + shell_m[i*2+1] * (32-i)) // (div * 16) % 256 for i in range(32)]
            if 119 in pairs:
                if check_key(pairs, f"pos_weight_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 7: The address has "GeCRiTz" - could be element symbols
# ============================================================================
print("\n[7] Address-based hints...")

# Ge=32, Cr=24, I=53, Tz=...
# Maybe use atomic numbers?
# Ge (Germanium) = 32
# C (Carbon) = 6
# Ri could be interpreted...

# Try using 32 and 6 as multipliers
shell_m = shell.copy()
shell_m[39] *= 32  # Ge
shell_m[52] *= 6   # C

for div in [32, 64, 128]:
    pairs = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(32)]
    if 119 in pairs:
        if check_key(pairs, f"atomic_ge_c_div{div}"):
            exit()

# ============================================================================
# Approach 8: Fibonacci-like operations
# ============================================================================
print("\n[8] Fibonacci-style recurrence...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64]:
            pairs = []
            prev = 0
            for i in range(32):
                current = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append((current + prev) % 256)
                prev = current

            if 119 in pairs:
                if check_key(pairs, f"fib_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 9: The "following" hint - maybe use prev+current pairing
# ============================================================================
print("\n[9] Following rectangles (prev+current)...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [32, 64]:
            # "following" might mean rect[i] + rect[i+1] where i is not consecutive pairs
            pairs = [(shell_m[i] + shell_m[i+1]) // div % 256 for i in range(0, 64, 2)]
            if check_key(pairs, f"following_m{mult40}_{mult53}_div{div}"):
                exit()

            # Or every rect with the one after
            pairs = [(shell_m[i] + shell_m[(i+1) % 64]) // div % 256 for i in range(32)]
            if check_key(pairs, f"follow_wrap_m{mult40}_{mult53}_div{div}"):
                exit()

# ============================================================================
# Approach 10: Different rect types for different bytes
# ============================================================================
print("\n[10] Mixed area types...")

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        outer_m = outer.copy()
        inner_m = inner.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53
        outer_m[39] *= mult40
        outer_m[52] *= mult53
        inner_m[39] *= mult40
        inner_m[52] *= mult53

        for div in [64, 128]:
            # First 16 from shell, next 16 from inner
            pairs1 = [(shell_m[i*2] + shell_m[i*2+1]) // div % 256 for i in range(16)]
            pairs2 = [(inner_m[(i+16)*2 % 64] + inner_m[(i+16)*2+1 % 64]) // div % 256 for i in range(16)]
            pairs = pairs1 + pairs2
            if 119 in pairs:
                if check_key(pairs, f"shell_inner_m{mult40}_{mult53}_div{div}"):
                    exit()

            # Alternating shell/outer
            pairs = []
            for i in range(32):
                if i % 2 == 0:
                    val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                else:
                    val = (outer_m[i*2] + outer_m[i*2+1]) // (div * 2) % 256
                pairs.append(val)
            if 119 in pairs:
                if check_key(pairs, f"alt_so_m{mult40}_{mult53}_div{div}"):
                    exit()

# ============================================================================
# Approach 11: Transaction amounts (555550 satoshis total, 4 transactions)
# ============================================================================
print("\n[11] Transaction-based hints...")

# 555550 = 5*111110 = 5*5*22222 = 25*22222
# Could be related to divisor

for mult40 in [1, 17]:
    for mult53 in [1, 6]:
        shell_m = shell.copy()
        shell_m[39] *= mult40
        shell_m[52] *= mult53

        for div in [55, 111, 222, 555]:
            pairs = [(shell_m[i*2] + shell_m[i*2+1]) % div for i in range(32)]
            if check_key(pairs, f"tx_mod{div}_m{mult40}_{mult53}"):
                exit()

# ============================================================================
# Approach 12: Could divisor be hidden in the puzzle itself?
# ============================================================================
print("\n[12] Self-referential divisors...")

# Use one of the shell values as divisor
for special_idx in [39, 52, 0, 63]:
    divisor = shell[special_idx]
    if divisor > 0:
        for mult40 in [1, 17]:
            for mult53 in [1, 6]:
                shell_m = shell.copy()
                shell_m[39] *= mult40
                shell_m[52] *= mult53

                pairs = [(shell_m[i*2] + shell_m[i*2+1]) // divisor % 256 for i in range(32)]
                if 119 in pairs:
                    if check_key(pairs, f"selfdiv{special_idx}_m{mult40}_{mult53}"):
                        exit()

print("\nCreative search complete.")
print("No solution found.")
