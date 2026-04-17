"""
Fresh angle: treat 64 rectangles as 64 hex nibbles of the 32-byte private key.
Also exploit the "4-bit output" model: each rect -> one nibble via (value // d) % 16
or a similar map.
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
    except Exception:
        return None


def count_match(addr):
    if not addr:
        return 0
    return sum(1 for a, b in zip(addr, TARGET) if a == b)


def check(nibbles, desc):
    if len(nibbles) != 64:
        return False
    if not all(0 <= n < 16 for n in nibbles):
        return False
    hex_str = ''.join(f'{n:x}' for n in nibbles)
    try:
        key = bytes.fromhex(hex_str)
    except Exception:
        return False
    for comp in (True, False):
        addr = privkey_to_address(key, comp)
        if addr == TARGET:
            print(f"\nSOLVED {desc}: {hex_str} comp={comp}")
            with open('/home/user/zden-puzzle/SOLUTION.txt', 'w') as f:
                f.write(f"{desc}\n{hex_str}\ncomp={comp}\n")
            return True
    return False


def score(nibbles):
    try:
        hex_str = ''.join(f'{n & 0xF:x}' for n in nibbles)
        key = bytes.fromhex(hex_str)
        return max(count_match(privkey_to_address(key, c)) for c in (True, False))
    except Exception:
        return 0


print("Nibble-decoding experiments")
best_overall = 0
best_desc = ""

# Try various single-source nibble extractions
sources = {'outer': outer, 'inner': inner, 'shell': shell}
# include modified shell (FIX: index 39 * 17)
shell_fix = shell.copy(); shell_fix[39] *= 17
sources['shell_fix39'] = shell_fix
shell_fix2 = shell.copy(); shell_fix2[39] *= 17; shell_fix2[57] *= 7
sources['shell_fix39_57'] = shell_fix2

# Try a variety of divisors and moduli
divisors = list(range(1, 32)) + [32, 39, 40, 57, 64, 100, 119, 127, 255]

for sname, src in sources.items():
    for d in divisors:
        for mode in ('div_mod16', 'mod16', 'digitsum_mod16', 'lastdigit'):
            nibbles = []
            ok = True
            for v in src:
                if mode == 'div_mod16':
                    n = (v // d) % 16
                elif mode == 'mod16':
                    n = (v % d) % 16 if d >= 16 else (v % 16)
                elif mode == 'digitsum_mod16':
                    s = sum(int(c) for c in str(v))
                    n = s % 16
                elif mode == 'lastdigit':
                    n = int(str(v)[-1]) % 16
                nibbles.append(n)
            s = score(nibbles)
            if s > best_overall:
                best_overall = s
                best_desc = f"{sname} d={d} mode={mode}"
                print(f"  {best_desc}: score={s}")
            if check(nibbles, best_desc):
                exit()

# Try pairing: each pair of consecutive rects -> a byte (high nibble + low nibble)
for sname, src in sources.items():
    for d1 in divisors:
        for d2 in divisors:
            nibbles = []
            for i in range(64):
                if i % 2 == 0:
                    nibbles.append((src[i] // d1) % 16)
                else:
                    nibbles.append((src[i] // d2) % 16)
            s = score(nibbles)
            if s > best_overall:
                best_overall = s
                best_desc = f"pair {sname} d1={d1} d2={d2}"
                print(f"  {best_desc}: score={s}")
            if check(nibbles, best_desc):
                exit()

# Use (outer - inner) / shell as ratio -> clamp
for d in divisors:
    nibbles = [((outer[i] * inner[i] // (shell[i] or 1)) // d) % 16 for i in range(64)]
    s = score(nibbles)
    if s > best_overall:
        best_overall = s; best_desc = f"ratio d={d}"
        print(f"  {best_desc}: score={s}")
    if check(nibbles, best_desc): exit()

# Dimensional interpretation: attempt to factor outer and assume thin shell
# key_nibble[i] = thickness_i (approx shell / perimeter)
for d in divisors:
    nibbles = []
    for i in range(64):
        approx_perim = 2 * (shell[i])  # placeholder - we don't know dims
        n = (shell[i] // d) % 16
        nibbles.append(n)
    s = score(nibbles)
    if s > best_overall:
        best_overall = s; best_desc = f"shell/{d}%16"
        print(f"  {best_desc}: score={s}")
    if check(nibbles, best_desc): exit()

print(f"\nBest score: {best_overall} - {best_desc}")
