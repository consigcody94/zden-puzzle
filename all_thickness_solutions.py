"""
For each rect, enumerate ALL integer (t_h, t_v) solutions to
   2*t_h*h + 2*t_v*w - 4*t_h*t_v = shell
where (w, h) = outer dims (from pixel) and shell = REPO_SHELL[i].

Then test different choice-strategies for the key:
- always visual (pixel-matching)
- always mathematical-alt (first non-visual)
- swap t_h <-> t_v
- pick the one whose thickness fits nibble range (0..15)
- combine first/second solutions in various orders
"""
import json, hashlib, ecdsa, base58

with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

w_out = [r['w_out'] for r in rects]
h_out = [r['h_out'] for r in rects]
t_h_pix = [r['t_horiz'] for r in rects]
t_v_pix = [r['t_vert'] for r in rects]

REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260, 434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770, 1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839, 660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868, 1642, 282, 912, 1598, 368, 1520, 1000, 656
]

# Enumerate ALL solutions for each rect (0 <= t_h, t_v <= max_side/2)
solutions = []
for i in range(64):
    w, h, s = w_out[i], h_out[i], REPO_SHELL[i]
    sols = []
    for th in range(0, w//2 + 1):
        for tv in range(0, h//2 + 1):
            if 2*th*h + 2*tv*w - 4*th*tv == s:
                sols.append((th, tv))
    solutions.append(sols)

print("Per-rect solution counts:")
print("idx | w x h | shell | #sols | solutions")
print("-"*80)
for i in range(64):
    sols = solutions[i]
    pix_match = (t_h_pix[i], t_v_pix[i])
    mark = ''
    if pix_match in sols:
        mark = '  (pixel_match)'
    # find closest pixel match even if not exact
    closest = None
    if sols:
        closest = min(sols, key=lambda s: abs(s[0]-t_h_pix[i])+abs(s[1]-t_v_pix[i]))
    flag = '' if closest == pix_match else f'  closest={closest}'
    print(f"{i:2d} | {w:3d}x{h:3d} | {s:4d} | {len(sols):2d} | {sols}{flag}")

# === Build various nibble sequences ===
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

best = 0; best_desc = ""

def try_nibs(nibs, name):
    global best, best_desc
    if len(nibs) != 64: return
    if not all(0 <= n < 16 for n in nibs):
        nibs = [n & 0xF for n in nibs]
    hx = ''.join(f'{n:x}' for n in nibs)
    try:
        kb = bytes.fromhex(hx)
    except: return
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = name
            print(f"  [{name}] {m}  {a}  key={hx[:20]}...")
        if a == TARGET:
            print(f"SOLVED {name}: {hx} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(f"{name}\n{hx}\ncomp={c}\n")
            raise SystemExit

# Strategy 1: Use the PIXEL thickness where it matches a solution,
# otherwise pick the solution closest to pixel.
strat_pixel_th = []
strat_pixel_tv = []
for i in range(64):
    sols = solutions[i] or [(0,0)]
    if (t_h_pix[i], t_v_pix[i]) in sols:
        c = (t_h_pix[i], t_v_pix[i])
    else:
        c = min(sols, key=lambda s: abs(s[0]-t_h_pix[i])+abs(s[1]-t_v_pix[i]))
    strat_pixel_th.append(c[0])
    strat_pixel_tv.append(c[1])

# Strategy 2: Use the SMALLEST solution (non-visual alt)
strat_min_th = []
strat_min_tv = []
for i in range(64):
    sols = solutions[i] or [(0,0)]
    c = min(sols, key=lambda s: s[0]+s[1])
    strat_min_th.append(c[0]); strat_min_tv.append(c[1])

# Strategy 3: Use the LARGEST (rare - but test)
strat_max_th = []
strat_max_tv = []
for i in range(64):
    sols = solutions[i] or [(0,0)]
    c = max(sols, key=lambda s: s[0]+s[1])
    strat_max_th.append(c[0]); strat_max_tv.append(c[1])

# Strategy 4: For rects with 2 solutions, pick the "alt" one (not the visual)
strat_alt_th = []
strat_alt_tv = []
for i in range(64):
    sols = solutions[i] or [(0,0)]
    visual = (t_h_pix[i], t_v_pix[i])
    if len(sols) > 1 and visual in sols:
        alt_candidates = [s for s in sols if s != visual]
        c = alt_candidates[0]
    elif sols:
        c = sols[0]
    else:
        c = (0, 0)
    strat_alt_th.append(c[0]); strat_alt_tv.append(c[1])

# Strategy 5: For rects with N solutions, try each and check if thickness fits nibble
strat_nib_th = []
strat_nib_tv = []
for i in range(64):
    sols = solutions[i] or [(0, 0)]
    # Prefer solutions where both fit in 0..15
    in_range = [s for s in sols if 0 <= s[0] < 16 and 0 <= s[1] < 16]
    if in_range:
        c = min(in_range, key=lambda s: s[0]+s[1])
    else:
        c = sols[0]
    strat_nib_th.append(c[0]); strat_nib_tv.append(c[1])

for name, lst in [
    ('pix_th', strat_pixel_th), ('pix_tv', strat_pixel_tv),
    ('min_th', strat_min_th),   ('min_tv', strat_min_tv),
    ('max_th', strat_max_th),   ('max_tv', strat_max_tv),
    ('alt_th', strat_alt_th),   ('alt_tv', strat_alt_tv),
    ('nib_th', strat_nib_th),   ('nib_tv', strat_nib_tv),
]:
    try_nibs(list(lst), name)
    try_nibs(list(reversed(lst)), name+'_rev')

# Bytes from (t_h, t_v) per rect (64 bytes, take 32)
print("\n=== 64-byte sources (t_h|t_v) ===")
def try_bytes(by, name):
    global best, best_desc
    if len(by) != 32: return
    kb = bytes(b & 0xFF for b in by)
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = name
            print(f"  [{name}] {m}  {a}  key={kb.hex()[:20]}...")
        if a == TARGET:
            print(f"SOLVED {name}: {kb.hex()} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(f"{name}\n{kb.hex()}\ncomp={c}\n")
            raise SystemExit

for strat_name, thl, tvl in [
    ('pixel', strat_pixel_th, strat_pixel_tv),
    ('min',   strat_min_th,   strat_min_tv),
    ('max',   strat_max_th,   strat_max_tv),
    ('alt',   strat_alt_th,   strat_alt_tv),
    ('nib',   strat_nib_th,   strat_nib_tv),
]:
    big = [((thl[i] & 0xF) << 4) | (tvl[i] & 0xF) for i in range(64)]
    try_bytes(big[:32], f"{strat_name}_th|tv_first32")
    try_bytes(big[32:], f"{strat_name}_th|tv_last32")
    try_bytes(big[::2], f"{strat_name}_th|tv_evens")
    try_bytes(big[1::2], f"{strat_name}_th|tv_odds")

    big2 = [((tvl[i] & 0xF) << 4) | (thl[i] & 0xF) for i in range(64)]
    try_bytes(big2[:32], f"{strat_name}_tv|th_first32")
    try_bytes(big2[32:], f"{strat_name}_tv|th_last32")

# Finally: the target's FIX hint says rect 40 has "17px thick line"
# Check each strategy to see if rect 39 is flagged/unusual
print("\nRect 39 (index 39, 'FIX/rect 40') solutions:")
print(f"  Pixel: {(t_h_pix[39], t_v_pix[39])}")
print(f"  All integer solutions: {solutions[39]}")
print(f"  W x H = {w_out[39]} x {h_out[39]}; shell={REPO_SHELL[39]}")

print(f"\nBest: {best} ({best_desc})")
