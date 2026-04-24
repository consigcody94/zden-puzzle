"""
Test: do per-rectangle thicknesses encode the private key?
Hypothesis families:
- 64 rects -> 64 nibbles of the 32-byte key (hex encoding)
- 64 rects -> 64 bytes (modulo some mapping)
- pairs of rects (with 'following' pairing) -> 32 bytes
Using true thicknesses (horizontal, vertical) from pixel extraction.
"""
import json, hashlib, ecdsa, base58

with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)
assert len(rects) == 64

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

t_h = [r['t_horiz'] for r in rects]
t_v = [r['t_vert'] for r in rects]
w_out = [r['w_out'] for r in rects]
h_out = [r['h_out'] for r in rects]
w_in = [r['w_in'] for r in rects]
h_in = [r['h_in'] for r in rects]
outer = [r['outer_area'] for r in rects]
inner = [r['inner_area'] for r in rects]
shell = [r['shell_area'] for r in rects]

# Repo's shell areas (authoritative)
REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260,
    434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770,
    1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839,
    660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868,
    1642, 282, 912, 1598, 368, 1520, 1000, 656
]

print("Distribution of thicknesses:")
print(f"  horizontal (t_h): min={min(t_h)} max={max(t_h)} unique={sorted(set(t_h))}")
print(f"  vertical   (t_v): min={min(t_v)} max={max(t_v)} unique={sorted(set(t_v))}")
print(f"  t_h[39]={t_h[39]}  t_v[39]={t_v[39]}  (rect 40, the FIX one)")
print()

# Also compute repo-implied thickness by solving:
#   shell = 2*t_h*h_out + 2*t_v*w_out - 4*t_h*t_v
# given w_out, h_out (from pixels, exact) and shell (from repo, exact).
# For each rect, enumerate small integer (t_h, t_v) that match.
def true_thicknesses(w, h, shell_target):
    best = []
    for th in range(0, 21):
        for tv in range(0, 21):
            if 2*th*h + 2*tv*w - 4*th*tv == shell_target:
                best.append((th, tv))
    return best

repo_th = [0]*64
repo_tv = [0]*64
for i, r in enumerate(rects):
    cands = true_thicknesses(r['w_out'], r['h_out'], REPO_SHELL[i])
    if cands:
        # prefer minimum thickness, tie break by horizontal
        th, tv = min(cands, key=lambda x: (x[0]+x[1], x[0]))
        repo_th[i], repo_tv[i] = th, tv
    else:
        repo_th[i], repo_tv[i] = -1, -1  # no match

print("Repo-implied (t_h, t_v):")
for i in range(64):
    flag = ' <-- FIX' if i == 39 else ''
    print(f"  {i:2d}: w_out={rects[i]['w_out']:3d} h_out={rects[i]['h_out']:3d}  t_h={repo_th[i]:2d} t_v={repo_tv[i]:2d}  shell={REPO_SHELL[i]:4d}{flag}")

print()
# How many thicknesses are 0..15? If thickness encodes a nibble directly, they should be 0..15.
valid_nibble_h = sum(1 for t in repo_th if 0 <= t <= 15)
valid_nibble_v = sum(1 for t in repo_tv if 0 <= t <= 15)
print(f"Valid nibble range: t_h {valid_nibble_h}/64, t_v {valid_nibble_v}/64")

# Helpers
def addr(k, c):
    try:
        sk = ecdsa.SigningKey.from_string(k, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if c:
            p = b'\x02' + vk.to_string()[:32] if vk.pubkey.point.y() % 2 == 0 else b'\x03' + vk.to_string()[:32]
        else:
            p = b'\x04' + vk.to_string()
        hh = hashlib.new('ripemd160'); hh.update(hashlib.sha256(p).digest())
        v = b'\x00' + hh.digest()
        cs = hashlib.sha256(hashlib.sha256(v).digest()).digest()[:4]
        return base58.b58encode(v + cs).decode()
    except: return None

def match(a):
    if not a: return 0
    return sum(1 for x,y in zip(a, TARGET) if x == y)

def check(byts, desc):
    kb = bytes(b % 256 for b in byts)
    for c in (True, False):
        a = addr(kb, c)
        if a == TARGET:
            print(f"\n*** SOLVED [{desc}] key={kb.hex()} comp={c} ***")
            open('/home/user/zden-puzzle/SOLUTION.txt', 'w').write(f"{desc}\n{kb.hex()}\ncomp={c}\n")
            return True
    return False

best = 0; best_desc = ""
tested = 0

def try_nibbles(nibs, name):
    global best, best_desc, tested
    if len(nibs) != 64:
        return
    tested += 1
    if not all(0 <= n < 16 for n in nibs):
        return
    key_hex = ''.join(f'{n:x}' for n in nibs)
    try:
        kb = bytes.fromhex(key_hex)
    except:
        return
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = name
            print(f"  [{name}] {m}  {a}  key={key_hex[:20]}...")
        if a == TARGET:
            print(f"SOLVED {name}: {key_hex} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt', 'w').write(f"{name}\n{key_hex}\ncomp={c}\n")
            exit()

def try_bytes(byts, name):
    global best, best_desc, tested
    if len(byts) != 32:
        return
    tested += 1
    kb = bytes(b % 256 for b in byts)
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = name
            print(f"  [{name}] {m}  {a}  key={kb.hex()[:20]}...")
        if a == TARGET:
            print(f"SOLVED {name}: {kb.hex()} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt', 'w').write(f"{name}\n{kb.hex()}\ncomp={c}\n")
            exit()

# ---------- NIBBLE HYPOTHESES ----------
# Using pixel-measured thicknesses (t_h, t_v) and repo-implied (repo_th, repo_tv)
print("\n=== Nibble hypotheses ===")

for label, tlist in [
    ('pixel_t_h', t_h),
    ('pixel_t_v', t_v),
    ('repo_t_h', repo_th),
    ('repo_t_v', repo_tv),
    ('pixel_sum',  [a+b for a,b in zip(t_h, t_v)]),
    ('repo_sum',   [a+b for a,b in zip(repo_th, repo_tv)]),
    ('pixel_max',  [max(a,b) for a,b in zip(t_h, t_v)]),
    ('pixel_min',  [min(a,b) for a,b in zip(t_h, t_v)]),
    ('pixel_xor',  [a^b for a,b in zip(t_h, t_v)]),
]:
    try_nibbles(list(tlist), label)
    # also try reversed
    try_nibbles(list(reversed(tlist)), label + '_rev')

# ---------- BYTE HYPOTHESES (pair each rect into a byte) ----------
print("\n=== Byte hypotheses (pairs of rects) ===")
for name, src in [
    ('repo_t_h', repo_th), ('repo_t_v', repo_tv),
    ('pixel_t_h', t_h),   ('pixel_t_v', t_v),
]:
    # byte[i] = src[2i]<<4 | src[2i+1]
    by = [((src[2*i] & 0xF) << 4) | (src[2*i+1] & 0xF) for i in range(32)]
    try_bytes(by, f"pair_seq_{name}")
    # reverse order
    sr = list(reversed(src))
    by = [((sr[2*i] & 0xF) << 4) | (sr[2*i+1] & 0xF) for i in range(32)]
    try_bytes(by, f"pair_seqrev_{name}")
    # interleaved evens & odds
    by = [((src[i] & 0xF) << 4) | (src[i+32] & 0xF) for i in range(32)]
    try_bytes(by, f"pair_halves_{name}")
    by = [((src[i] & 0xF) << 4) | (src[63-i] & 0xF) for i in range(32)]
    try_bytes(by, f"pair_mirror_{name}")

# ---------- COMBINED: t_h & t_v as two nibbles of a byte ----------
print("\n=== Combined t_h|t_v as byte ===")
for name, thl, tvl in [
    ('pixel', t_h, t_v),
    ('repo', repo_th, repo_tv),
]:
    # byte[i] = t_h[i] << 4 | t_v[i] -- 64 bytes
    by64 = [((thl[i] & 0xF) << 4) | (tvl[i] & 0xF) for i in range(64)]
    # Try first 32 of them, last 32, odds, evens
    try_bytes(by64[:32], f"{name}_th|tv_first32")
    try_bytes(by64[32:], f"{name}_th|tv_last32")
    try_bytes(by64[::2], f"{name}_th|tv_even")
    try_bytes(by64[1::2], f"{name}_th|tv_odd")
    # other order tv|th
    by64b = [((tvl[i] & 0xF) << 4) | (thl[i] & 0xF) for i in range(64)]
    try_bytes(by64b[:32], f"{name}_tv|th_first32")
    try_bytes(by64b[32:], f"{name}_tv|th_last32")

# ---------- (-I * X + LXIV) / x with real dims ----------
# Interpretations:
#   I = thickness, X = a scaling factor, LXIV = 64, x = dividend
# Try: byte[i] = (-t_h[i]*t_v[i] + 64) / something
#      nibble[i] = (-t_h[i] + 64) / t_v[i] if t_v > 0 else 64
print("\n=== Formula-based (-I*X + LXIV)/x ===")
for name, I, X, x in [
    ('pixel_t_h*t_v / 64', t_h, t_v, [64]*64),
    ('repo_t_h*t_v / 64', repo_th, repo_tv, [64]*64),
]:
    vals = []
    for i in range(64):
        xi = x[i] if x[i] else 1
        vals.append((-I[i]*X[i] + 64) % 256)
    try_bytes(vals[:32], f"{name}_first32")

# Another family: treat each rect's "key value" as simple transformed bytes
# nibble[i] = (64 - (t_h+t_v)) mod 16
for name, thl, tvl in [('pixel', t_h, t_v), ('repo', repo_th, repo_tv)]:
    nibs = [(64 - thl[i] - tvl[i]) % 16 for i in range(64)]
    try_nibbles(nibs, f"(64 - th-tv) mod 16 [{name}]")
    nibs = [(thl[i] * tvl[i]) % 16 for i in range(64)]
    try_nibbles(nibs, f"(th*tv) mod 16 [{name}]")

print(f"\nTested {tested} candidates; best = {best} ({best_desc})")
