"""
Final geometric sweep: pair 'following' rects (various orderings) and try
concrete formula evaluations using real per-rect dimensions.

Interpretations of -I *X+ LXIV /x/ (I'll write F(a, b) where a, b are two
following rects):

  F1: (-I_a * X_b + 64) / x_b              where I=inner, X=outer, x=shell
  F2: (-t_h_a * t_v_b + 64) / t_v_b
  F3: (-a + 64) / b                        (simplest)
  F4: (a * 10 - 64) / b                    (X as Roman 10)
  F5: (I_a + X_b + 64) % x                 etc.

The goal is NOT to brute-force millions more — it's to prove we've tried
the natural readings with real geometry. Best score reported.
"""
import json, hashlib, ecdsa, base58

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

REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260, 434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770, 1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839, 660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868, 1642, 282, 912, 1598, 368, 1520, 1000, 656
]
shell = REPO_SHELL

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

best = 0
best_desc = ""
tested = 0

def test(by, desc):
    global best, best_desc, tested
    tested += 1
    if len(by) != 32: return
    kb = bytes(b & 0xFF for b in by)
    for c in (True, False):
        a = addr(kb, c)
        m = match(a)
        if m > best:
            best = m; best_desc = desc
            print(f"  [{desc}] {m} {a} key={kb.hex()[:20]}...")
        if a == TARGET:
            print(f"SOLVED {desc}: {kb.hex()} comp={c}")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(f"{desc}\n{kb.hex()}\ncomp={c}\n")
            raise SystemExit

# Pairings (32 pairs each, using all 64 rects exactly once)
def pair_consec(arr):      return [(arr[2*i], arr[2*i+1]) for i in range(32)]
def pair_halves(arr):      return [(arr[i], arr[32+i]) for i in range(32)]
def pair_mirror(arr):      return [(arr[i], arr[63-i]) for i in range(32)]
def pair_step(arr, k):
    used=[False]*64; pairs=[]
    for i in range(64):
        if used[i]: continue
        j=(i+k)%64
        if used[j] or j==i: continue
        pairs.append((arr[i], arr[j])); used[i]=used[j]=True
        if len(pairs)==32: break
    return pairs if len(pairs)==32 else None

pair_fns = {
    'consec': pair_consec,
    'halves': pair_halves,
    'mirror': pair_mirror,
    'step3': lambda a: pair_step(a, 3),
    'step7': lambda a: pair_step(a, 7),
    'step17': lambda a: pair_step(a, 17),
    'step32': lambda a: pair_step(a, 32),
    'step39': lambda a: pair_step(a, 39),
}

# Attribute sources per rect
attrs = {
    'outer': outer,
    'inner': inner,
    'shell': shell,
    'w_out': w_out,
    'h_out': h_out,
    'w_in': w_in,
    'h_in': h_in,
    't_h': t_h,
    't_v': t_v,
}

# Formulas operating on (va, vb) = paired values, returning a byte
def eval_formula(va, vb, fid):
    if fid == 'sum_div7':   return (va+vb) // 7
    if fid == 'sum_div64':  return (va+vb) // 64
    if fid == 'diff':       return abs(va-vb)
    if fid == 'xor':        return va ^ vb
    if fid == 'and_mod':    return (va & vb)
    if fid == 'neg_a_plus_64_div_b': return ((-va + 64) // max(vb,1))
    if fid == 'neg_ab_plus_64':      return (-va*vb + 64)
    if fid == 'neg_a_x_plus_64_mod': return ((-va*10 + 64))
    if fid == 'a_plus_b_mod_64':     return (va + vb) % 64
    if fid == 'a_times_b':  return va * vb
    if fid == 'a_plus_b_div64_plus_x': return (va + vb) // 64 + 1
    return 0

FORMULAS = [
    'sum_div7','sum_div64','diff','xor','and_mod',
    'neg_a_plus_64_div_b','neg_ab_plus_64','neg_a_x_plus_64_mod',
    'a_plus_b_mod_64','a_times_b',
]

print("Sweeping attribute x pairing x formula combinations...")
for aname, arr in attrs.items():
    for pname, pfn in pair_fns.items():
        pairs = pfn(arr)
        if pairs is None: continue
        for fid in FORMULAS:
            try:
                by = [eval_formula(a, b, fid) % 256 for a, b in pairs]
            except Exception:
                continue
            test(by, f"{aname}|{pname}|{fid}")

# Also: two-attribute formulas:
# e.g. byte[i] = (-t_h[a]*t_v[a] + t_h[b]*t_v[b] + 64) / shell[a]
print("\nTwo-attribute formulas:")
for pname, pfn in pair_fns.items():
    # get pairs as indices
    pairs = pfn(list(range(64)))
    if pairs is None: continue
    # Several formula ideas
    for fid in range(10):
        by = []
        for a, b in pairs:
            try:
                if fid == 0: v = (-t_h[a]*t_v[a] + t_h[b]*t_v[b] + 64) // max(shell[a], 1)
                elif fid == 1: v = (-inner[a] + 64) // max(shell[a], 1)
                elif fid == 2: v = (-outer[a] * t_h[b] + 64) // max(shell[b], 1)
                elif fid == 3: v = (shell[a] + shell[b]) // 7
                elif fid == 4: v = (outer[a] - inner[a] - 64) // max(t_h[a]+t_v[a], 1)
                elif fid == 5: v = (shell[a] // max(t_h[a]+t_v[a], 1))
                elif fid == 6: v = (w_out[a] * h_out[a] - w_in[b] * h_in[b])
                elif fid == 7: v = (t_h[a] * 16 + t_v[a]) + (t_h[b] * 16 + t_v[b])
                elif fid == 8: v = ((-1)*(t_h[a] + t_v[a]) + 64) // max(t_h[b] + t_v[b], 1)
                elif fid == 9: v = (outer[a] + outer[b]) // 64
                else: v = 0
                by.append(v % 256)
            except:
                by.append(0)
        test(by, f"2attr_{pname}_f{fid}")

print(f"\nFinal sweep: tested={tested} best={best} ({best_desc})")
