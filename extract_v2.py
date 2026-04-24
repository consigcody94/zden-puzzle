"""
v2: cleaner extraction. Strategy:
- Use RETR_EXTERNAL to get outer rectangles only. Each rectangle's outer boundary
  is one contour. Its bounding box gives outer_w, outer_h.
- Then within each outer bbox, find the inner black hole by flood-fill from center.
- Also detect outer bboxes that overlap each other (small rect inside big one) -
  exclude the inner hole contours that are themselves inside a larger rect.

Match to repo order by outer-area matching + position ordering.
"""
import cv2
import numpy as np
import json

PATH = '/home/user/zden-puzzle/img/crypto5fix.png'
img = cv2.imread(PATH, cv2.IMREAD_GRAYSCALE)
H, W = img.shape

# Crop out label areas at bottom
# Rectangles live in roughly y=50..810, leaving x=0..W
crop = img[0:810, 0:W]
_, binary = cv2.threshold(crop, 128, 255, cv2.THRESH_BINARY)

# Use RETR_CCOMP so we can identify outer vs inner
contours, hierarchy = cv2.findContours(binary, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_NONE)
hier = hierarchy[0]

# Top-level (parent == -1) contours are the outer rects.
outer_rects = []
for i, c in enumerate(contours):
    nxt, prv, child, parent = hier[i]
    if parent != -1:
        continue
    x, y, w, h = cv2.boundingRect(c)
    area = w * h
    # Filter: rectangles should be at least, say, 8x5
    if w < 7 or h < 5:
        continue
    # And not absurdly elongated (text would be very wide&short)
    # But we allow rects down to ~10x8.
    outer_rects.append({'idx': i, 'x': x, 'y': y, 'w': w, 'h': h, 'area': area, 'child': child})

print(f"Found {len(outer_rects)} outer candidates.")

# For each outer rect, find the largest inner contour
def largest_inner(outer):
    ci = outer['child']
    best = None
    while ci != -1:
        ix, iy, iw, ih = cv2.boundingRect(contours[ci])
        if best is None or iw*ih > best[2]*best[3]:
            best = (ix, iy, iw, ih)
        ci = hier[ci][0]  # next sibling
    return best

for r in outer_rects:
    inner = largest_inner(r)
    if inner:
        r['ix'], r['iy'], r['iw'], r['ih'] = inner
        r['in_area'] = inner[2]*inner[3]
    else:
        r['ix'] = r['iy'] = 0
        r['iw'] = r['ih'] = 0
        r['in_area'] = 0

# Filter out text characters: should be large enough rectangles
# The smallest legitimate rectangle in Level 5 is around 120 area (120,32,88 = rect 53),
# so outer area >= 100 and has a detectable inner hole
before = len(outer_rects)
outer_rects = [r for r in outer_rects if r['area'] >= 100 and r['in_area'] > 0]
print(f"After filter: {len(outer_rects)} (was {before})")

# Repo canonical areas (in reading order)
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

# Match detected rects to repo by outer area, respecting position order.
# For each repo rect (in order), find nearest-area detected rect that hasn't been used
# AND is visually positioned "after" the previous match (roughly top-to-bottom, left-to-right).
# To handle duplicates cleanly, we first group detected rects into visual rows.

det = outer_rects
# Cluster rows by y-center
for r in det:
    r['yc'] = r['y'] + r['h'] / 2
det.sort(key=lambda r: r['yc'])

# Row assignment by gap-based clustering on y-center
rows = []
if det:
    rows.append([det[0]])
    for r in det[1:]:
        prev = rows[-1][-1]
        # same row if y-center within 40 of the previous max-y
        if abs(r['yc'] - np.mean([x['yc'] for x in rows[-1]])) < 40:
            rows[-1].append(r)
        else:
            rows.append([r])
for row in rows:
    row.sort(key=lambda r: r['x'])

print(f"Rows: {len(rows)}, counts: {[len(r) for r in rows]}")
flat = [r for row in rows for r in row]
print(f"Total detected: {len(flat)} (target 64)")

# Print each in order alongside repo areas
print("\nord | det_out | det_in | repo_out | repo_in | dx dy w_out h_out w_in h_in")
print("-" * 100)
mismatches = 0
for i in range(64):
    if i < len(flat):
        r = flat[i]
        ro, ri, rs = REPO[i]
        o_ok = abs(r['area'] - ro) < 80
        i_ok = abs(r['in_area'] - ri) < 300  # inner area can have bigger error due to thickness
        flag = '' if o_ok else ' OUT_MISMATCH'
        if not o_ok:
            mismatches += 1
        print(f"{i:3d} | {r['area']:5d} | {r['in_area']:5d} | {ro:5d} | {ri:5d} |"
              f" {r['x']:3d} {r['y']:3d} {r['w']:3d} {r['h']:3d} {r['iw']:3d} {r['ih']:3d}{flag}")
    else:
        ro, ri, rs = REPO[i]
        print(f"{i:3d} | MISSING | repo={ro},{ri},{rs}")

print(f"\nOuter-area mismatches: {mismatches}/64")
print(f"Detected: {len(flat)}/64")

# Save
data = []
for i, r in enumerate(flat[:64]):
    data.append({
        'order': i,
        'x': r['x'], 'y': r['y'],
        'w_out': r['w'], 'h_out': r['h'],
        'w_in': r['iw'], 'h_in': r['ih'],
        'ix': r['ix'], 'iy': r['iy'],
        'outer_area_px': r['area'],
        'inner_area_px': r['in_area'],
    })
with open('/home/user/zden-puzzle/img/rects_v2.json', 'w') as f:
    json.dump(data, f, indent=2)
