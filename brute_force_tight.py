"""
Very tight brute forcer:

Strategy per rect i:
  - If there is 1 integer thickness solution: that's the nibble value.
  - If multiple: take EXACTLY 2 candidates (visual pixel+1 match, and smallest alt).
  - For rects 39 and 52: fix candidate to a set of 'likely' values.

Per-rect nibble offsets: try both +0 and +1 globally (shifts all rects).
Assemblies: t_h source or t_v source; forward or reversed order.

Target space ~ 2^26 * ~4 fixup combos * 8 assembly variants = ~2 billion
CPU-feasible in a reasonable budget.
"""
import json, hashlib, os, sys, time, multiprocessing as mp
from coincurve import PrivateKey
import base58

TARGET_ADDR = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"
TARGET_H160 = base58.b58decode(TARGET_ADDR)[1:21]
print(f"target hash160 = {TARGET_H160.hex()}")

with open('/home/user/zden-puzzle/img/hypothesis_space.json') as f:
    hyp = json.load(f)
with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

def h160(pub):
    return hashlib.new('ripemd160', hashlib.sha256(pub).digest()).digest()

# Likely values for rects 39 and 52 (no integer solutions)
# hints: 17 px line (0x11), 0x77, 0x28, 0x40 (=64) appearing in the puzzle
FIX_39_OPTS = [0, 1, 7, 0x7, 0x11 & 0xF, 0x0, 8, 15]
FIX_52_OPTS = [0, 7, 8, 15, 1]

def build_choices(kind, offset):
    choices = []
    for i, p in enumerate(hyp):
        if p['n_sols'] == 0:
            # fixed later per variant
            choices.append(None)
            continue
        pix = rects[i]['t_horiz'] if kind == 't_h' else rects[i]['t_vert']
        target = pix + 1
        key = 'th_vals' if kind == 't_h' else 'tv_vals'
        vals = sorted(set(p[key]))
        if not vals:
            choices.append([0]); continue
        A = min(vals, key=lambda v: abs(v - target))
        alt = [v for v in vals if v != A]
        if alt:
            B = min(alt, key=lambda v: abs(v - pix))
            cand = sorted({A + offset, B + offset})
        else:
            cand = [A + offset]
        cand = sorted({v & 0xF for v in cand})
        choices.append(cand)
    return choices

def space_size(choices, fix39, fix52):
    s = 1
    for i, c in enumerate(choices):
        if c is None:
            if i == 39: s *= len(fix39)
            elif i == 52: s *= len(fix52)
        else:
            s *= len(c)
    return s

def iter_combs(choices, fix39, fix52, start, stop):
    n = len(choices)
    # make effective choice list
    eff = []
    for i, c in enumerate(choices):
        if c is None:
            eff.append(fix39 if i == 39 else fix52 if i == 52 else [0])
        else:
            eff.append(c)
    radixes = [len(c) for c in eff]
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
    (choices, fix39, fix52, start, stop, wid, assembly) = args
    checked = 0
    t0 = time.time()
    for nibs in iter_combs(choices, fix39, fix52, start, stop):
        if assembly == 'rev':
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
        if checked and checked % 400000 == 0:
            dt = time.time() - t0
            print(f"  [w{wid}:{assembly}] {checked:>9,} ({checked/dt/1000:.0f}k/s)")
    return None

def run(kind, offset, assembly, fix39, fix52, budget):
    choices = build_choices(kind, offset)
    total = space_size(choices, fix39, fix52)
    tag = f"{kind}+{offset}_{assembly}_f39={fix39}_f52={fix52}"
    print(f"\n--- [{tag}] space={total:,} budget={budget}s ---")
    n_workers = os.cpu_count() or 8
    shard_size = (total + n_workers - 1) // n_workers
    tasks = []
    for w in range(n_workers):
        s = w * shard_size
        e = min(s + shard_size, total)
        if s >= e: break
        tasks.append((choices, fix39, fix52, s, e, w, assembly))

    ctx = mp.get_context('fork')
    start = time.time()
    with ctx.Pool(n_workers) as pool:
        async_result = pool.map_async(worker, tasks)
        while True:
            if async_result.ready():
                break
            if time.time() - start > budget:
                pool.terminate(); pool.join()
                print(f"  [{tag}] timed out")
                return None
            time.sleep(1)
        results = async_result.get()
    for r in results:
        if r is not None:
            kindfound, key = r
            print(f"\n*** SOLVED [{tag}]: {key.hex()} ({kindfound}) ***")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(
                f"{tag}\n{key.hex()}\n{kindfound}\n")
            return key
    print(f"  [{tag}] done in {time.time()-start:.0f}s")
    return None

if __name__ == '__main__':
    budget = int(os.environ.get('BUDGET', '180'))
    variants = []
    # Prioritize the most plausible first
    for kind in ('t_h', 't_v'):
        for offset in (1, 0):   # +1 first (math-thickness hypothesis)
            for assembly in ('fwd', 'rev'):
                for f39 in [[0], [7], [1], [0,7,1]]:
                    for f52 in [[0], [7], [1], [0,7,1]]:
                        variants.append((kind, offset, assembly, f39, f52))
    print(f"Total variants to try: {len(variants)}")
    total_budget = int(os.environ.get('TOTAL_BUDGET', '1200'))
    t_start = time.time()
    for i, (k, o, a, f39, f52) in enumerate(variants, 1):
        if time.time() - t_start > total_budget:
            print(f"\nTotal budget exhausted after {i-1} variants")
            break
        print(f"\n[{i}/{len(variants)}]")
        sol = run(k, o, a, f39, f52, budget)
        if sol:
            sys.exit(0)
    print("\nNo solution found.")
