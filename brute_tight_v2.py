"""
Tight v2 brute forcer.

For each rect:
  - If 1 integer thickness solution exists: use it (nibble = t_h or t_v).
  - If >1: pick AT MOST 2 candidates: (A) nearest to pixel+1, (B) nearest to pixel.
For rects 39 and 52 (no integer solutions): fix to a small set of candidates.

Variants tried in order (most plausible first):
  kind in (t_h, t_v) x offset in (0, 1) x order in (fwd, rev) x
  [rect39 in {fix_set}] x [rect52 in {fix_set}]

Space per single variant (w/o 39,52 fix): up to 2^27 ≈ 134M.
"""
import json, hashlib, os, sys, time, multiprocessing as mp
from coincurve import PrivateKey
import base58

TARGET_ADDR = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"
TARGET_H160 = base58.b58decode(TARGET_ADDR)[1:21]

with open('/home/user/zden-puzzle/img/sensible.json') as f:
    sens = json.load(f)
with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

def h160(pub):
    return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()

def build_tight(kind, offset):
    """Per-rect: at most 2 nibble candidates.
    kind: 't_h' or 't_v'
    offset: 0 or 1 (adds to each value)
    """
    choices = []
    for i in range(64):
        s = sens[i]
        if not s['sols']:
            choices.append(None)  # fix-later for rects 39 and 52
            continue
        vals_key = 'th_set' if kind == 't_h' else 'tv_set'
        vals = s[vals_key]  # already filtered to 0..15
        if not vals:
            choices.append([0]); continue
        pix = rects[i]['t_horiz'] if kind == 't_h' else rects[i]['t_vert']
        A = min(vals, key=lambda v: abs(v - (pix+1)))
        alt = [v for v in vals if v != A]
        if alt:
            B = min(alt, key=lambda v: abs(v - pix))
            cand = sorted({(A + offset) & 0xF, (B + offset) & 0xF})
        else:
            cand = [(A + offset) & 0xF]
        # dedupe
        cand = sorted(set(cand))
        choices.append(cand)
    return choices

def space_size(choices, fix39, fix52):
    s = 1
    for i, c in enumerate(choices):
        if c is None:
            if i == 39: s *= len(fix39)
            elif i == 52: s *= len(fix52)
            else: s *= 1
        else:
            s *= len(c)
    return s

def effective(choices, fix39, fix52):
    eff = []
    for i, c in enumerate(choices):
        if c is None:
            if i == 39: eff.append(fix39)
            elif i == 52: eff.append(fix52)
            else: eff.append([0])
        else:
            eff.append(c)
    return eff

def iter_combs(eff, start, stop):
    n = len(eff); radixes = [len(c) for c in eff]
    idx = [0]*n
    rem = start
    for i in range(n-1, -1, -1):
        idx[i] = rem % radixes[i]
        rem //= radixes[i]
    for k in range(start, stop):
        yield [eff[i][idx[i]] for i in range(n)]
        for i in range(n-1, -1, -1):
            idx[i] += 1
            if idx[i] < radixes[i]: break
            idx[i] = 0

def worker(args):
    eff, start, stop, wid, order = args
    checked = 0; t0 = time.time()
    for nibs in iter_combs(eff, start, stop):
        if order == 'rev':
            nibs = list(reversed(nibs))
        hex_s = ''.join(f'{n:x}' for n in nibs)
        try:
            k = bytes.fromhex(hex_s)
            pk = PrivateKey(k)
            if h160(pk.public_key.format(compressed=True)) == TARGET_H160:
                return ('compressed', k)
            if h160(pk.public_key.format(compressed=False)) == TARGET_H160:
                return ('uncompressed', k)
        except Exception:
            pass
        checked += 1
        if checked and checked % 500000 == 0:
            dt = time.time() - t0
            print(f"    [w{wid}] {checked:>9,} ({checked/dt/1000:.0f}k/s)")
    return None

def run_variant(kind, offset, order, fix39, fix52, budget):
    choices = build_tight(kind, offset)
    eff = effective(choices, fix39, fix52)
    total = 1
    for c in eff: total *= len(c)
    tag = f"{kind}+{offset}_{order}_f39={fix39}_f52={fix52}"
    print(f"\n[{tag}] space={total:,} budget={budget}s")

    n_workers = os.cpu_count() or 8
    shard = (total + n_workers - 1) // n_workers
    tasks = []
    for w in range(n_workers):
        s = w * shard; e = min(s + shard, total)
        if s >= e: break
        tasks.append((eff, s, e, w, order))
    ctx = mp.get_context('fork')
    t0 = time.time()
    with ctx.Pool(n_workers) as pool:
        ar = pool.map_async(worker, tasks)
        while not ar.ready():
            if time.time() - t0 > budget:
                pool.terminate(); pool.join()
                print(f"  [{tag}] timed out")
                return None
            time.sleep(1)
        res = ar.get()
    for r in res:
        if r:
            which, key = r
            print(f"\n*** SOLVED [{tag}]: {key.hex()} ({which}) ***")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(
                f"{tag}\n{key.hex()}\n{which}\n")
            return key
    print(f"  [{tag}] done in {time.time()-t0:.0f}s")
    return None

if __name__ == '__main__':
    budget_var = int(os.environ.get('BUDGET', '60'))
    total_budget = int(os.environ.get('TOTAL', '900'))

    variants = []
    # Most plausible first
    for kind in ('t_h',):             # try t_h only first
        for offset in (1, 0):          # +1 first (math thickness)
            for order in ('fwd', 'rev'):
                for f39 in ([0], [7], [1]):
                    for f52 in ([0], [7], [1]):
                        variants.append((kind, offset, order, f39, f52))
    for kind in ('t_v',):
        for offset in (1, 0):
            for order in ('fwd', 'rev'):
                for f39 in ([0],):
                    for f52 in ([0],):
                        variants.append((kind, offset, order, f39, f52))

    t_start = time.time()
    for i, v in enumerate(variants, 1):
        if time.time() - t_start > total_budget:
            print(f"\nTotal budget exhausted at variant {i-1}/{len(variants)}")
            break
        print(f"\n[{i}/{len(variants)}]")
        sol = run_variant(*v, budget=budget_var)
        if sol:
            sys.exit(0)
    print(f"\nDone; no solution across {len(variants)} variants")
