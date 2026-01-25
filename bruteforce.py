"""
Focused brute force - trying specific byte modifications.
"""
import hashlib
import ecdsa
import base58
import random
import time

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
print("FOCUSED BRUTE FORCE")
print("="*70)

# Best base key
shell_m = shell.copy()
shell_m[39] *= 17
base = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

print(f"Base key: {bytes(base).hex()}")
print(f"First byte: {hex(base[0])}, Byte 19: {hex(base[19])}")

# ============================================================================
# 1. Two-byte exhaustive at all position pairs
# ============================================================================
print("\n[1] Two-byte exhaustive search (excluding 0 and 19)...")

start_time = time.time()
count = 0

# Positions to try (excluding 0 and 19 which have correct values)
positions = [i for i in range(32) if i not in [0, 19]]

for p1_idx in range(len(positions)):
    p1 = positions[p1_idx]
    for p2_idx in range(p1_idx + 1, len(positions)):
        p2 = positions[p2_idx]
        for v1 in range(256):
            for v2 in range(256):
                pairs = base.copy()
                pairs[p1] = v1
                pairs[p2] = v2
                if check_key(pairs, f"2b_{p1}_{p2}_{v1}_{v2}"):
                    exit()
                count += 1

        if count % 1000000 == 0:
            elapsed = time.time() - start_time
            print(f"  {count/1000000:.0f}M combinations, {elapsed:.1f}s")

print(f"  Total: {count} combinations, no solution")

# ============================================================================
# 2. Try different base formulas with 2-byte mod
# ============================================================================
print("\n[2] Different formulas with 2-byte search...")

formulas = [
    ("div10", lambda sm, i: (sm[i*2] + sm[i*2+1]) // 10 % 256),
    ("div17", lambda sm, i: (sm[i*2] + sm[i*2+1]) // 17 % 256),
    ("nomult", lambda sm, i: (shell[i*2] + shell[i*2+1]) // 7 % 256),
]

for name, formula in formulas:
    if name == "nomult":
        base2 = [formula(shell, i) for i in range(32)]
    else:
        base2 = [formula(shell_m, i) for i in range(32)]

    print(f"\n  Trying {name}: first={hex(base2[0])}")

    # Quick 2-byte search on key positions
    for p1 in [1, 10, 20, 31]:
        for p2 in [5, 15, 25]:
            if p1 == p2:
                continue
            for v1 in range(256):
                for v2 in range(256):
                    pairs = base2.copy()
                    pairs[p1] = v1
                    pairs[p2] = v2
                    if check_key(pairs, f"{name}_{p1}_{p2}"):
                        exit()

print("  No solution")

print("\n" + "="*70)
print("Brute force complete - no solution")
print("="*70)
