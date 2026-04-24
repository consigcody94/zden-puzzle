"""
Exhaustive thickness-based formula tests using TRUE per-rect dimensions.

Using:
- pixel measurements (w_out, h_out, t_h, t_v from pixel extraction)
- repo shell areas (authoritative)

Formula families to test:
- 64 thicknesses -> 64 nibbles
- 64 thicknesses -> 32 bytes (pair them with various pairings)
- Formula (-I*X + LXIV)/x with many substitutions
"""
import json, hashlib, ecdsa, base58, itertools

with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

w_out = [r['w_out'] for r in rects]
h_out = [r['h_out'] for r in rects]
w_in = [r['w_in'] for r in rects]
h_in = [r['h_in'] for r in rects]
t_h = [r['t_horiz'] for r in rects]
t_v = [r['t_vert'] for r in rects]
outer = [r['outer_area'] for r in rects]
inner = [r['inner_area'] for r in rects]
shell_px = [r['shell_area'] for r in rects]

REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260, 434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770, 1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839, 660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868, 1642, 282, 912, 1598, 368, 1520, 1000, 656
]
REPO_OUTER = [r['outer_area'] for r in rects]
REPO_INNER = [REPO_OUTER[i] - REPO_SHELL[i] for i in range(64)]

# Cached repo thicknesses via dimension factoring
def true_th(w, h, shell_target, max_t=25):
    best = []
    for th in range(0, max_t+1):
        for tv in range(0, max_t+1):
            if 2*th*h + 2*tv*w - 4*th*tv == shell_target:
                best.append((th, tv))
    return best

repo_th = [0]*64
repo_tv = [0]*64
repo_th2 = [0]*64  # asymmetric alt
repo_tv2 = [0]*64
for i in range(64):
    cands = true_th(w_out[i], h_out[i], REPO_SHELL[i])
    if cands:
        # take the solution with min thickness
        cands.sort(key=lambda x: x[0]+x[1])
        repo_th[i], repo_tv[i] = cands[0]
        if len(cands) > 1:
            repo_th2[i], repo_tv2[i] = cands[1]
        else:
            repo_th2[i], repo_tv2[i] = cands[0]
    else:
        repo_th[i], repo_tv[i] = t_h[i], t_v[i]  # fallback
        repo_th2[i], repo_tv2[i] = t_h[i], t_v[i]

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
    return sum(1 for x,y in zip(a, TARGET) if x == y) if a else 0

best = 0; best_desc = ""; tested = 0
def test_key(kb, desc):
    global best, best_desc, tested
    tested += 1
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = desc
            print(f"  [{desc}] {m}  {a}  key={kb.hex()[:30]}...")
        if a == TARGET:
            print(f"SOLVED {desc}: {kb.hex()} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(f"{desc}\n{kb.hex()}\ncomp={c}\n")
            raise SystemExit

def try_nibbles(nibs, name):
    if len(nibs) != 64: return
    if not all(0 <= n < 16 for n in nibs):
        # clamp mod16
        nibs = [n & 0xF for n in nibs]
    hex_s = ''.join(f'{n:x}' for n in nibs)
    try:
        test_key(bytes.fromhex(hex_s), name)
    except ValueError:
        return

def try_bytes(by, name):
    if len(by) != 32: return
    test_key(bytes(b % 256 for b in by), name)

# -------------- Nibble sources --------------
nibble_sources = {
    'pixel_t_h':   [t & 0xF for t in t_h],
    'pixel_t_v':   [t & 0xF for t in t_v],
    'repo_t_h':    [t & 0xF for t in repo_th],
    'repo_t_v':    [t & 0xF for t in repo_tv],
    'repo_t_h2':   [t & 0xF for t in repo_th2],
    'repo_t_v2':   [t & 0xF for t in repo_tv2],
    'pix_sum_tht_v':[(a+b) & 0xF for a,b in zip(t_h, t_v)],
    'repo_sum':    [(a+b) & 0xF for a,b in zip(repo_th, repo_tv)],
    'pix_max':     [max(a,b) & 0xF for a,b in zip(t_h, t_v)],
    'pix_xor':     [(a^b) & 0xF for a,b in zip(t_h, t_v)],
    'repo_xor':    [(a^b) & 0xF for a,b in zip(repo_th, repo_tv)],
    'w_out_mod16': [w & 0xF for w in w_out],
    'h_out_mod16': [h & 0xF for h in h_out],
    'w_in_mod16':  [w & 0xF for w in w_in],
    'h_in_mod16':  [h & 0xF for h in h_in],
    'shell_mod16': [s & 0xF for s in REPO_SHELL],
    'outer_mod16': [o & 0xF for o in REPO_OUTER],
    'inner_mod16': [i & 0xF for i in REPO_INNER],
    # 64 - t formulas
    '64_minus_th_div_tv':[((64 - t_h[i]) // max(t_v[i],1)) & 0xF for i in range(64)],
    '64_minus_tv_div_th':[((64 - t_v[i]) // max(t_h[i],1)) & 0xF for i in range(64)],
}

print("=== Nibble direct tests ===")
for name, nibs in nibble_sources.items():
    try_nibbles(list(nibs), name)
    try_nibbles(list(reversed(nibs)), name+'_rev')

# Row-column transposes (8x8 grid)
def transpose8(lst):
    out = [0]*64
    for i in range(64):
        r, c = i // 8, i % 8
        out[c*8 + r] = lst[i]
    return out

print("\n=== Nibble transposes ===")
for name in ['pixel_t_h','repo_t_h','repo_t_v','pixel_t_v','pix_max']:
    base = nibble_sources[name]
    try_nibbles(transpose8(base), name+'_transpose')
    try_nibbles(transpose8(list(reversed(base))), name+'_rev_transpose')

# Per-byte from (nibA, nibB) pairings of thickness arrays
def pair_variants(arr):
    return {
        'seq':       [(arr[2*i], arr[2*i+1]) for i in range(32)],
        'mirror':    [(arr[i], arr[63-i]) for i in range(32)],
        'halves':    [(arr[i], arr[32+i]) for i in range(32)],
        'even_odd':  [(arr[2*i], arr[2*i+1]) for i in range(32)],
        'adj_1':     [(arr[i], arr[(i+1) % 64]) for i in range(0, 64, 2)],
        'row_col':   [(arr[r*8+c], arr[c*8+r]) for r in range(8) for c in range(8) if r < c][:32],  # 28 items, padded
    }

print("\n=== Byte tests from nibble pairings ===")
for name, arr in [('repo_th', repo_th), ('repo_tv', repo_tv), ('pix_th', t_h), ('pix_tv', t_v)]:
    for pname, pairs in pair_variants(arr).items():
        if len(pairs) != 32: continue
        by = [((a & 0xF) << 4) | (b & 0xF) for a,b in pairs]
        try_bytes(by, f"{name}_{pname}")
        by = [((b & 0xF) << 4) | (a & 0xF) for a,b in pairs]
        try_bytes(by, f"{name}_{pname}_flip")

# Combined t_h|t_v per rect
print("\n=== Per-rect t_h|t_v byte (64 rects -> 64 bytes, take 32) ===")
for name, thl, tvl in [('pixel', t_h, t_v), ('repo', repo_th, repo_tv), ('repo2', repo_th2, repo_tv2)]:
    big = [((thl[i] & 0xF) << 4) | (tvl[i] & 0xF) for i in range(64)]
    for desc, sub in [
        ('first32', big[:32]),
        ('last32',  big[32:]),
        ('even',    big[::2]),
        ('odd',     big[1::2]),
        ('first32_rev', list(reversed(big[:32]))),
    ]:
        try_bytes(sub, f"{name}_th|tv_{desc}")
    big2 = [((tvl[i] & 0xF) << 4) | (thl[i] & 0xF) for i in range(64)]
    for desc, sub in [
        ('first32', big2[:32]),
        ('last32',  big2[32:]),
        ('even',    big2[::2]),
        ('odd',     big2[1::2]),
    ]:
        try_bytes(sub, f"{name}_tv|th_{desc}")

# "Sum of two following rectangles" with thicknesses (no wrap-around arithmetic)
print("\n=== Sum of two 'following' rectangles (thickness space) ===")
for name, arr in [('repo_th', repo_th), ('repo_tv', repo_tv), ('pix_th', t_h), ('pix_tv', t_v)]:
    # Following = next rect after skip k
    for skip in [1, 2, 3, 7, 8, 9, 11, 16, 17, 32]:
        used = [False]*64
        pairs = []
        for i in range(64):
            if used[i]: continue
            j = (i + skip) % 64
            if used[j] or j == i: continue
            pairs.append((arr[i], arr[j]))
            used[i] = used[j] = True
            if len(pairs) == 32: break
        if len(pairs) != 32: continue
        # as byte from pair summed
        by_sum = [(a + b) % 256 for a,b in pairs]
        try_bytes(by_sum, f"{name}_skip{skip}_sum")
        by_nib = [((a & 0xF) << 4) | (b & 0xF) for a,b in pairs]
        try_bytes(by_nib, f"{name}_skip{skip}_nib")

# Formula (-I * X + LXIV) / x with concrete geometry pieces
print("\n=== Formula -I*X + LXIV / x (concrete substitutions) ===")
# Interpret: I = t_h, X = t_v, LXIV = 64, x = ???
# Try nibble[i] = (-t_h[i] * t_v[i] + 64) mod 256 ...
for name, thl, tvl in [('pix', t_h, t_v), ('repo', repo_th, repo_tv)]:
    # byte per rect using -th*tv + 64
    raw = [(-thl[i]*tvl[i] + 64) for i in range(64)]
    try_nibbles([x & 0xF for x in raw], f"{name}_-th*tv+64_nib")
    try_bytes([x & 0xFF for x in raw[:32]], f"{name}_-th*tv+64_byte_first32")
    try_bytes([x & 0xFF for x in raw[32:]], f"{name}_-th*tv+64_byte_last32")
    # (-I*X + 64) / X
    raw2 = [(-thl[i]*tvl[i] + 64) // max(tvl[i],1) for i in range(64)]
    try_nibbles([x & 0xF for x in raw2], f"{name}_(-th*tv+64)/tv_nib")
    try_bytes([x & 0xFF for x in raw2[:32]], f"{name}_(-th*tv+64)/tv_byte")
    # For each pair, (-t_h[a]*t_h[b] + 64) / t_v[a]  etc.
    # Following-pair: i paired with i+1
    for skip in [1, 2, 7, 32]:
        pairs = [(i, (i+skip)%64) for i in range(0, 64, 2)][:32]
        if len(pairs) != 32: continue
        # Formula byte[i] = (-th[a] * th[b] + 64) / max(tv[a],1)
        by = [((-thl[a]*thl[b] + 64) // max(tvl[a],1)) & 0xFF for a,b in pairs]
        try_bytes(by, f"{name}_skip{skip}_formula")

print(f"\nTotal tested: {tested}; best = {best} ({best_desc})")
