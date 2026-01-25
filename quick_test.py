"""
Quick test with flushed output.
"""
import hashlib
import ecdsa
import base58
import random
import sys

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
    if len(byte_list) != 32 or not all(0 <= b <= 255 for b in byte_list):
        return False
    privkey_bytes = bytes(byte_list)
    for compressed in [True, False]:
        addr = privkey_to_address(privkey_bytes, compressed)
        if addr == TARGET:
            print(f"\nSOLVED! {desc}")
            print(f"Key: {privkey_bytes.hex()}")
            with open("C:/Users/Public/SOLUTION.txt", "w") as f:
                f.write(f"Solution: {desc}\nKey: {privkey_bytes.hex()}\n")
            return True
    return False

def count_match(addr):
    return sum(1 for a, b in zip(addr or "", TARGET) if a == b)

print("Starting search...", flush=True)

# Step-3 base with pos23=176 (10 char match)
indices = [(57 + i * 3) % 64 for i in range(32)]
base_key = [shell[idx] // 7 % 256 for idx in indices]
base_key[23] = 176

print(f"Base: {bytes(base_key).hex()}", flush=True)
print(f"Base match: {count_match(privkey_to_address(bytes(base_key), True))}", flush=True)

# Try 2-byte exhaustive
best = 10
print("\n2-byte exhaustive on step3 base...", flush=True)

for p1 in range(32):
    for p2 in range(p1+1, 32):
        for v1 in range(0, 256, 4):  # Coarser for speed
            for v2 in range(0, 256, 4):
                key = base_key.copy()
                key[p1] = v1
                key[p2] = v2

                for comp in [True, False]:
                    addr = privkey_to_address(bytes(key), comp)
                    match = count_match(addr)
                    if match > best:
                        best = match
                        c = "C" if comp else "U"
                        print(f"p{p1}={v1},p{p2}={v2}[{c}]: {match} - {addr[:18]}", flush=True)

                    if check_key(key, f"{p1}_{v1}_{p2}_{v2}"):
                        sys.exit(0)

    if p1 % 4 == 3:
        print(f"Progress: p1={p1}, best={best}", flush=True)

print(f"\nBest: {best}", flush=True)
