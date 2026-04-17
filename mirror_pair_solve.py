"""
Hint: 'sum of two ~~consecutive~~ following rectangles'.
Interpretation: each rect pairs with a rect that FOLLOWS it per some rule,
not adjacent pairing. Combined with formula '-I *X+ LXIV /x/' where LXIV=64,
the most natural reading is 64-I (mirror).

Try all natural 'following' pairings and formulas.
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
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

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
    except:
        return None

def match(a):
    if not a: return 0
    return sum(1 for x,y in zip(a, TARGET) if x == y)

def check(k, desc):
    kb = bytes(b % 256 for b in k)
    for c in (True, False):
        a = addr(kb, c)
        if a == TARGET:
            print(f"\n*** SOLVED {desc} key={kb.hex()} comp={c} ***")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(f"{desc}\n{kb.hex()}\ncomp={c}\n")
            return True
    return False

best = 0; best_desc = ""
attempts = 0

# Pairing strategies for "following" (not consecutive)
def pair_mirror(src):
    # rect[i] + rect[63 - i] for i in 0..31
    return [(src[i], src[63 - i]) for i in range(32)]

def pair_halves(src):
    # rect[i] + rect[i + 32]
    return [(src[i], src[i + 32]) for i in range(32)]

def pair_interleaved(src):
    # rect[2i] + rect[2i+1] (the "consecutive" baseline - for comparison)
    return [(src[2*i], src[2*i+1]) for i in range(32)]

def pair_follow_step(src, step):
    # rect[i] + rect[(i + step) % 64], where i chosen so we use each rect exactly once
    # Simple: take i = 0..31, partner = i + step (only valid if step>=32 or rotation yields set cover)
    pairs = []
    used = set()
    i = 0
    while len(pairs) < 32 and i < 64:
        if i in used:
            i += 1; continue
        j = (i + step) % 64
        if j == i or j in used:
            i += 1; continue
        pairs.append((src[i], src[j]))
        used.add(i); used.add(j); i += 1
    return pairs if len(pairs) == 32 else None

# Formulas applied to each pair (a, b) -> byte
def formula_variants(a, b, divisor):
    yield ('sum', (a + b) // divisor)
    yield ('diff', abs(a - b) // divisor)
    yield ('-1*a+b/div', ((-1*a + b) // divisor) if divisor else 0)
    yield ('(-a+64)/b', ((-a + 64) // b) if b else 0)
    yield ('(64-a)/b', ((64 - a) // b) if b else 0)
    yield ('(-a*b+64)/div', ((-a*b + 64) // divisor) if divisor else 0)
    yield ('sum*64/div', ((a+b)*64 // divisor) if divisor else 0)

# Sources
def make_sources():
    out = {}
    # FIX variants: multiply rect 39 by X; optionally rect 57 by 7
    for m39 in (1, 17):
        for m57 in (1, 7, 6):
            key = f"shell_m39={m39}_m57={m57}"
            s = shell.copy(); s[39] *= m39; s[57] *= m57
            out[key] = s
    out['outer'] = outer
    out['inner'] = inner
    out['outer_plus_inner'] = [outer[i]+inner[i] for i in range(64)]
    return out

sources = make_sources()

pair_strategies = [
    ('mirror', pair_mirror),
    ('halves', pair_halves),
    ('step17', lambda s: pair_follow_step(s, 17)),
    ('step32', lambda s: pair_follow_step(s, 32)),
    ('step39', lambda s: pair_follow_step(s, 39)),
    ('consecutive_baseline', pair_interleaved),
]

divisors = [1, 2, 4, 7, 8, 10, 16, 17, 32, 64, 119, 127]

for sname, src in sources.items():
    for pname, pfn in pair_strategies:
        pairs = pfn(src)
        if pairs is None: continue
        for div in divisors:
            for formula_name, _dummy in formula_variants(0, 0, 1):
                pass
            # Apply each formula
            for div2 in [div]:
                # collect 32 bytes per formula
                by_formula = {}
                for a, b in pairs:
                    for fname, val in formula_variants(a, b, div2):
                        by_formula.setdefault(fname, []).append(val % 256)
                for fname, bytes_list in by_formula.items():
                    attempts += 1
                    m = max(match(addr(bytes(x % 256 for x in bytes_list), c)) for c in (True, False))
                    desc = f"{sname}|{pname}|{fname}|div={div2}"
                    if m > best:
                        best = m; best_desc = desc
                        print(f"  [{attempts}] {desc}: {m}")
                    if check(bytes_list, desc):
                        print(f"Total attempts: {attempts}")
                        exit()

print(f"\nAttempts={attempts}  best={best}  ({best_desc})")
