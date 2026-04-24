"""
Compute exact hypothesis space size under 'thickness = nibble' hypothesis.

For each rect, enumerate distinct t_h values and distinct t_v values from the
integer solutions of 2*t_h*h + 2*t_v*w - 4*t_h*t_v = shell.

Rects 39 and 52 have no solutions -> we must pick from 0..15 per ambiguous nibble.
"""
import json
with open('/home/user/zden-puzzle/img/rects_v3.json') as f:
    rects = json.load(f)

REPO_SHELL = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260, 434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770, 1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839, 660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868, 1642, 282, 912, 1598, 368, 1520, 1000, 656
]

def solutions(w, h, s):
    sols = []
    for th in range(0, max(w,h)+1):
        for tv in range(0, max(w,h)+1):
            if 2*th*h + 2*tv*w - 4*th*tv == s:
                sols.append((th, tv))
    return sols

per_rect = []
for i, r in enumerate(rects):
    s = REPO_SHELL[i]
    sols = solutions(r['w_out'], r['h_out'], s)
    th_vals = sorted(set(t[0] for t in sols))
    tv_vals = sorted(set(t[1] for t in sols))
    # For nibble: only values 0..15
    th_nib = [v for v in th_vals if 0 <= v < 16]
    tv_nib = [v for v in tv_vals if 0 <= v < 16]
    per_rect.append({
        'idx': i, 'w': r['w_out'], 'h': r['h_out'], 'shell': s,
        'n_sols': len(sols), 'th_vals': th_vals, 'tv_vals': tv_vals,
        'th_nib': th_nib, 'tv_nib': tv_nib,
    })

# Compute combination space for t_h-nibble hypothesis
prod_th = 1
prod_tv = 1
ambig_th = 0
ambig_tv = 0
for p in per_rect:
    n_th = max(1, len(p['th_nib']))
    n_tv = max(1, len(p['tv_nib']))
    # if 0 solutions, nibble is free -> 16 choices
    if p['n_sols'] == 0:
        n_th = 16; n_tv = 16
    prod_th *= n_th
    prod_tv *= n_tv
    if n_th > 1: ambig_th += 1
    if n_tv > 1: ambig_tv += 1

print(f"{'idx':>3} {'w x h':>7} {'shell':>5} {'#sols':>5} th={{vals}} tv={{vals}}")
for p in per_rect:
    print(f"{p['idx']:3d} {p['w']:3d}x{p['h']:<3d} {p['shell']:5d} {p['n_sols']:5d}"
          f"  th={p['th_nib']} tv={p['tv_nib']}")

print()
print(f"t_h-nibble hypothesis space: {prod_th:,}")
print(f"t_v-nibble hypothesis space: {prod_tv:,}")
print(f"Ambiguous rects by t_h: {ambig_th}/64 ; by t_v: {ambig_tv}/64")

# A tighter variant: trust pixel thickness where present, only vary rects 39 and 52
pix_mismatch = 0
for i, p in enumerate(per_rect):
    if p['n_sols'] == 0: continue
    pix_th = rects[i]['t_horiz']
    if pix_th not in p['th_nib']:
        pix_mismatch += 1

print(f"\nRects where pixel t_h is NOT in integer solution set: {pix_mismatch}")

# Save space definition for brute forcer
import json
with open('/home/user/zden-puzzle/img/hypothesis_space.json', 'w') as f:
    json.dump(per_rect, f, indent=2)
print("Saved hypothesis_space.json")
