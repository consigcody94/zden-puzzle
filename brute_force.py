"""
GPU-ready brute forcer for Zden Level 5.

Two-phase approach:
  PHASE A: deterministic candidates (fast, ~dozens of tries):
           try pixel+k offsets, swapped t_h/t_v, known fixups.
  PHASE B: full thickness-ambiguity enumeration, multiprocessing,
           single-flight coincurve contexts per worker.

Outputs a SOLUTION.txt if the target hash160 is matched.

Designed so phase B can be replaced with a CUDA kernel if GPU is available.
"""
import json, hashlib, struct, os, sys, time, itertools, multiprocessing as mp
from coincurve import PrivateKey

# --- Target ---
import base58
TARGET_ADDR = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"
decoded = base58.b58decode(TARGET_ADDR)
TARGET_H160 = decoded[1:21]
print(f"target hash160 = {TARGET_H160.hex()}")

# --- Load hypothesis space ---
with open('/home/user/zden-puzzle/img/hypothesis_space.json') as f:
    hyp = json.load(f)
with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260, 434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770, 1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839, 660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868, 1642, 282, 912, 1598, 368, 1520, 1000, 656
]

# --- Hashing helpers ---
def h160(pubkey_bytes):
    return hashlib.new('ripemd160', hashlib.sha256(pubkey_bytes).digest()).digest()

def check_key(priv_bytes):
    """Return matching address kind if key solves the puzzle, else None."""
    try:
        pk = PrivateKey(priv_bytes)
    except Exception:
        return None
    # compressed
    try:
        pub_c = pk.public_key.format(compressed=True)
        if h160(pub_c) == TARGET_H160:
            return 'compressed'
    except Exception:
        pass
    try:
        pub_u = pk.public_key.format(compressed=False)
        if h160(pub_u) == TARGET_H160:
            return 'uncompressed'
    except Exception:
        pass
    return None

# --- PHASE A: deterministic candidates ---
def phase_a():
    print("\n=== PHASE A: deterministic candidates ===")
    t_h_pix = [r['t_horiz'] for r in rects]
    t_v_pix = [r['t_vert'] for r in rects]

    # Build several base 64-nibble sequences from different interpretations
    candidates = []
    for label, nibs in [
        ('pix_th',           t_h_pix),
        ('pix_tv',           t_v_pix),
        ('pix_th+1',         [(t+1) & 0xF for t in t_h_pix]),
        ('pix_tv+1',         [(t+1) & 0xF for t in t_v_pix]),
        ('pix_th-1',         [(t-1) & 0xF for t in t_h_pix]),
        ('pix_th+1_rev',     list(reversed([(t+1) & 0xF for t in t_h_pix]))),
        ('pix_tv+1_rev',     list(reversed([(t+1) & 0xF for t in t_v_pix]))),
        ('pix_max+1',        [(max(a,b)+1)&0xF for a,b in zip(t_h_pix, t_v_pix)]),
        ('pix_min+1',        [(min(a,b)+1)&0xF for a,b in zip(t_h_pix, t_v_pix)]),
        ('pix_sum+1',        [((a+b)+1)&0xF for a,b in zip(t_h_pix, t_v_pix)]),
        ('pix_xor+1',        [((a^b)+1)&0xF for a,b in zip(t_h_pix, t_v_pix)]),
        ('(pix_th+1)^(pix_tv+1)', [((a+1)^(b+1))&0xF for a,b in zip(t_h_pix, t_v_pix)]),
    ]:
        if len(nibs) == 64:
            nibs = [n & 0xF for n in nibs]
            hex_s = ''.join(f'{n:x}' for n in nibs)
            candidates.append((label, bytes.fromhex(hex_s)))

    # Pack (t_h+1, t_v+1) as one byte per rect, take first 32
    big = [(((a+1)&0xF)<<4)|((b+1)&0xF) for a,b in zip(t_h_pix, t_v_pix)]
    candidates.append(('th+1|tv+1_first32', bytes(big[:32])))
    candidates.append(('th+1|tv+1_last32',  bytes(big[32:])))
    candidates.append(('th+1|tv+1_evens',   bytes(big[::2])))
    candidates.append(('th+1|tv+1_odds',    bytes(big[1::2])))

    big2 = [(((b+1)&0xF)<<4)|((a+1)&0xF) for a,b in zip(t_h_pix, t_v_pix)]
    candidates.append(('tv+1|th+1_first32', bytes(big2[:32])))
    candidates.append(('tv+1|th+1_last32',  bytes(big2[32:])))

    print(f"checking {len(candidates)} deterministic candidates...")
    for label, key in candidates:
        r = check_key(key)
        if r:
            print(f"*** SOLVED by [{label}]: {key.hex()} ({r}) ***")
            open('/home/user/zden-puzzle/SOLUTION.txt','w').write(
                f"{label}\n{key.hex()}\n{r}\n")
            return key
        # log short
        # print(f"  {label}: {key.hex()[:16]}... no")
    return None

# --- PHASE B: sharded brute force over ambiguous thicknesses ---
# Hypothesis: each rect contributes one nibble = t_h (from the integer-solution set).
# For rects with 0 solutions (39, 52), try all 0..15.
# We shard by fixing the choices of a leading block of rects.
#
# Choice vectors: for each rect we have a list of possible nibble values.

def make_choice_lists(kind='th'):
    """kind in {'th','tv'} - one nibble per rect."""
    choices = []
    for i, p in enumerate(hyp):
        if p['n_sols'] == 0:
            choices.append(list(range(16)))  # free
        else:
            vals = p['th_nib'] if kind == 'th' else p['tv_nib']
            # keep only 0..15 and dedupe
            vals = sorted({v & 0xF for v in vals})
            if not vals:
                vals = list(range(16))
            choices.append(vals)
    return choices

def space_size(choices):
    s = 1
    for c in choices:
        s *= len(c)
    return s

def iterate_combinations(choices, start, stop):
    """Mixed-radix iterator: yield combinations [start, stop)."""
    n = len(choices)
    radixes = [len(c) for c in choices]
    idx = [0]*n
    # decode `start` to idx
    rem = start
    for i in range(n-1, -1, -1):
        idx[i] = rem % radixes[i]
        rem //= radixes[i]
    for k in range(start, stop):
        yield [choices[i][idx[i]] for i in range(n)]
        # increment
        for i in range(n-1, -1, -1):
            idx[i] += 1
            if idx[i] < radixes[i]:
                break
            idx[i] = 0

def worker(args):
    choices, start, stop, worker_id = args
    # local copy for speed
    keys_checked = 0
    last_report = time.time()
    for nibs in iterate_combinations(choices, start, stop):
        hex_s = ''.join(f'{n:x}' for n in nibs)
        try:
            k = bytes.fromhex(hex_s)
            pk = PrivateKey(k)
            pub_c = pk.public_key.format(compressed=True)
            if h160(pub_c) == TARGET_H160:
                return ('compressed', k)
            pub_u = pk.public_key.format(compressed=False)
            if h160(pub_u) == TARGET_H160:
                return ('uncompressed', k)
        except Exception:
            pass
        keys_checked += 1
        if keys_checked % 200000 == 0:
            now = time.time()
            rate = 200000 / (now - last_report) if now > last_report else 0
            last_report = now
            print(f"  [worker {worker_id}] checked {keys_checked:>10,} "
                  f"(rate {rate/1000:.0f}k/s)")
    return None

def phase_b(kind='th', total_budget_seconds=600, n_workers=None):
    print(f"\n=== PHASE B ({kind}-nibble), budget={total_budget_seconds}s ===")
    if n_workers is None:
        n_workers = os.cpu_count() or 8
    choices = make_choice_lists(kind)
    total = space_size(choices)
    print(f"total combinations: {total:,}")
    print(f"workers: {n_workers}")

    # Measure throughput with a small probe (single worker)
    probe_n = 20000
    t0 = time.time()
    for nibs in iterate_combinations(choices, 0, probe_n):
        hex_s = ''.join(f'{n:x}' for n in nibs)
        k = bytes.fromhex(hex_s)
        try:
            pk = PrivateKey(k)
            pk.public_key.format(compressed=True)
        except Exception:
            pass
    probe_time = time.time() - t0
    probe_rate = probe_n / probe_time
    effective_rate = probe_rate * n_workers
    print(f"probe single-thread rate: {probe_rate:.0f}/s ; effective {n_workers}-core: {effective_rate/1000:.0f}k/s")

    feasible_n = int(effective_rate * total_budget_seconds * 0.9)
    feasible_n = min(feasible_n, total)
    print(f"will attempt ~{feasible_n:,} of {total:,} combinations ({100*feasible_n/total:.4f}%)")

    # Shard the [0, feasible_n) range across workers
    shard_size = (feasible_n + n_workers - 1) // n_workers
    tasks = []
    for w in range(n_workers):
        s = w * shard_size
        e = min(s + shard_size, feasible_n)
        if s >= e:
            break
        tasks.append((choices, s, e, w))

    ctx = mp.get_context('fork')
    with ctx.Pool(n_workers) as pool:
        for result in pool.imap_unordered(worker, tasks):
            if result is not None:
                kind_solved, key = result
                print(f"\n*** SOLVED ({kind_solved}): {key.hex()} ***")
                open('/home/user/zden-puzzle/SOLUTION.txt','w').write(
                    f"phase_b_{kind}\n{key.hex()}\n{kind_solved}\n")
                pool.terminate()
                return key
    return None

if __name__ == '__main__':
    t0 = time.time()
    sol = phase_a()
    if sol:
        print(f"DONE in {time.time()-t0:.1f}s")
        sys.exit(0)

    # PHASE B on t_h
    budget = int(os.environ.get('BUDGET', '300'))  # 5 min default
    sol = phase_b('th', total_budget_seconds=budget)
    if sol:
        print(f"DONE in {time.time()-t0:.1f}s")
        sys.exit(0)

    # PHASE B on t_v (different hypothesis)
    sol = phase_b('tv', total_budget_seconds=budget)
    if sol:
        print(f"DONE in {time.time()-t0:.1f}s")
        sys.exit(0)

    print(f"\nNo solution in {time.time()-t0:.1f}s (budget {budget}s per phase)")
