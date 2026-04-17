"""
Interpret mini-puzzle 09111819 FIX 11122111 as a direct XOR or additive
correction applied to a base key derived from rects.
09111819 -> 8 digits that could be 4 bytes: 09 11 18 19.
11122111 -> 1 11 22 11 1 or 11 12 21 11.
Also try 0-9-1-1-1-8-1-9 and 1-1-1-2-2-1-1-1 as 8 bytes.
"""
import hashlib, ecdsa, base58

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

def addr(k, c):
    try:
        sk = ecdsa.SigningKey.from_string(k, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if c:
            p = b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]
        else:
            p = b'\x04' + vk.to_string()
        h = hashlib.new('ripemd160'); h.update(hashlib.sha256(p).digest())
        v = b'\x00' + h.digest()
        cs = hashlib.sha256(hashlib.sha256(v).digest()).digest()[:4]
        return base58.b58encode(v + cs).decode()
    except: return None

def match(a):
    if not a: return 0
    return sum(1 for x,y in zip(a, TARGET) if x == y)

# Base key: standard pairs
fix_variants = [
    ("FIX_39x17", [17 if i == 39 else 1 for i in range(64)]),
    ("FIX_39x7_57x7", [7 if i in (39, 57) else 1 for i in range(64)]),
    ("FIX_40x17", [17 if i == 40 else 1 for i in range(64)]),
]
seq1_variants = [
    [0x09,0x11,0x18,0x19],
    [0x11,0x12,0x21,0x11],
    [9,11,18,19,11,12,21,11],
    [0,9,1,1,1,8,1,9,1,1,1,2,2,1,1,1],
    [0x09,0x11,0x18,0x19,0x11,0x12,0x21,0x11],
]

best = 0
best_desc = ""
tested = 0

for name, mults in fix_variants:
    sm = [shell[i] * mults[i] for i in range(64)]
    for div in [1, 7, 10, 17, 64, 127]:
        # pair-sum
        base_pairs = [(sm[2*i] + sm[2*i+1]) // div for i in range(32)]
        # pair-diff
        base_diff = [abs(sm[2*i] - sm[2*i+1]) // div for i in range(32)]
        # single high-byte
        base_single = [sm[2*i] // div for i in range(32)]

        for base_name, base in [("sum", base_pairs), ("diff", base_diff), ("single", base_single)]:
            for seq in seq1_variants:
                # Apply as XOR pattern at various start positions
                for start in range(33 - min(len(seq), 32)):
                    for op in ("xor", "add", "sub"):
                        k = [b % 256 for b in base]
                        for j, sv in enumerate(seq):
                            if start + j >= 32: break
                            if op == "xor":
                                k[start+j] = k[start+j] ^ (sv & 0xff)
                            elif op == "add":
                                k[start+j] = (k[start+j] + sv) % 256
                            else:
                                k[start+j] = (k[start+j] - sv) % 256
                        tested += 1
                        kb = bytes(k)
                        for c in (True, False):
                            a = addr(kb, c)
                            m = match(a)
                            if m > best:
                                best = m
                                best_desc = f"{name}/{div}/{base_name}/{op}@{start}"
                                print(f"  {best_desc}: {m}  {a}")
                            if a == TARGET:
                                print(f"SOLVED: {kb.hex()} comp={c}")
                                exit()

print(f"\nTested {tested}; best={best} ({best_desc})")
