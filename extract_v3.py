"""
v3: Extract ALL 64 rects including the last row.
- Crop y=0..900 to include bottom row.
- Mask out the formula box (bottom-left) and logo (bottom-right).
"""
import cv2
import numpy as np
import json

PATH = '/home/user/zden-puzzle/img/crypto5fix.png'
img = cv2.imread(PATH, cv2.IMREAD_GRAYSCALE)
H, W = img.shape

# Work on full image; we'll filter contours by position
_, binary = cv2.threshold(img, 128, 255, cv2.THRESH_BINARY)

# Mask the formula box (bottom-left) and logo (bottom-right) by zeroing those regions.
# Formula box area is roughly x=25..95, y=780..890 (7x11 small glyphs in pixel font style).
# Logo is roughly x=800..940, y=780..910.
# Also mask bottom center text region (y=900..950).
b2 = binary.copy()
b2[780:, 0:150] = 0  # formula box corner
b2[780:, 780:] = 0   # logo corner
b2[900:, :] = 0      # text at bottom

contours, hierarchy = cv2.findContours(b2, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_NONE)
hier = hierarchy[0]

outer_rects = []
for i, c in enumerate(contours):
    nxt, prv, child, parent = hier[i]
    if parent != -1:
        continue
    x, y, w, h = cv2.boundingRect(c)
    if w < 7 or h < 5:
        continue
    area = w * h
    outer_rects.append({'idx': i, 'x': x, 'y': y, 'w': w, 'h': h, 'area': area, 'child': child})

def largest_inner(outer):
    ci = outer['child']
    best = None
    while ci != -1:
        ix, iy, iw, ih = cv2.boundingRect(contours[ci])
        if best is None or iw*ih > best[2]*best[3]:
            best = (ix, iy, iw, ih)
        ci = hier[ci][0]
    return best

for r in outer_rects:
    inner = largest_inner(r)
    if inner:
        r['ix'], r['iy'], r['iw'], r['ih'] = inner
        r['in_area'] = inner[2]*inner[3]
    else:
        r['ix'] = r['iy'] = r['iw'] = r['ih'] = 0
        r['in_area'] = 0

# Filter: keep only rects with an inner hole AND area >= 100
outer_rects = [r for r in outer_rects if r['in_area'] > 0 and r['area'] >= 100]
print(f"{len(outer_rects)} rects after filter")

# Cluster by y-center using per-row threshold
for r in outer_rects:
    r['yc'] = r['y'] + r['h']/2
outer_rects.sort(key=lambda r: r['yc'])

rows = []
if outer_rects:
    rows.append([outer_rects[0]])
    for r in outer_rects[1:]:
        row_mean_y = np.mean([x['yc'] for x in rows[-1]])
        if abs(r['yc'] - row_mean_y) < 50:
            rows[-1].append(r)
        else:
            rows.append([r])
for row in rows:
    row.sort(key=lambda r: r['x'])
print(f"Rows: {len(rows)} counts: {[len(r) for r in rows]}")

flat = [r for row in rows for r in row]
print(f"Flat: {len(flat)}")

REPO = [
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

print("\nidx | pixel    | repo    | diff_out | diff_in | wOut hOut wIn hIn t_lr t_tb")
print("-"*100)
misses = 0
data = []
for i in range(64):
    if i >= len(flat):
        ro, ri, rs = REPO[i]
        print(f"{i:2d} | MISSING                           | repo={ro},{ri},{rs}")
        misses += 1
        continue
    r = flat[i]
    ro, ri, rs = REPO[i]
    t_lr = (r['w'] - r['iw']) // 2
    t_tb = (r['h'] - r['ih']) // 2
    shell_px = r['area'] - r['in_area']
    do = r['area'] - ro
    di = r['in_area'] - ri
    flag = ' MISMATCH' if abs(do) > 80 else ''
    if flag:
        misses += 1
    print(f"{i:2d} | {r['area']:5d},{r['in_area']:5d},{shell_px:5d} | {ro:5d},{ri:5d},{rs:5d} |"
          f" {do:+4d} | {di:+4d} | {r['w']:3d} {r['h']:3d} {r['iw']:3d} {r['ih']:3d}  t={t_lr},{t_tb}{flag}")
    data.append({
        'order': i,
        'x': r['x'], 'y': r['y'],
        'w_out': r['w'], 'h_out': r['h'],
        'w_in': r['iw'], 'h_in': r['ih'],
        't_horiz': t_lr, 't_vert': t_tb,
        'outer_area': r['area'],
        'inner_area': r['in_area'],
        'shell_area': shell_px,
    })

print(f"\nMismatches/misses: {misses}/64")
with open('/home/user/zden-puzzle/img/rects_v3.json', 'w') as f:
    json.dump(data, f, indent=2)
