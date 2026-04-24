"""
Extract per-rectangle geometry from the puzzle image.

Strategy:
- Binarize the image (white borders vs black background + inner black regions).
- Find connected white components; each rectangle's border is one connected component.
- For each, get bounding box (outer w/h), then detect the inner black hole to get inner w/h.
- Compute thickness = (w_outer - w_inner) / 2 etc.

We'll crop out the bottom label area first so the text doesn't pollute results.
"""
import cv2
import numpy as np

PATH = '/home/user/zden-puzzle/img/crypto5fix.png'
img = cv2.imread(PATH, cv2.IMREAD_GRAYSCALE)
print("image shape:", img.shape)

# Crop bottom labels (formula box on left, logo on right, text)
# The rectangles region goes roughly from y=0 to y~820; below that is branding.
H, W = img.shape
crop = img[0:820, 0:W].copy()
# Also mask out the left formula box and right logo regions if within crop
# They appear at the bottom but let's be safe — the rects live roughly y=50..800, x=180..770
# Just restrict to center to be safe
cv2.imwrite('/home/user/zden-puzzle/img/cropped.png', crop)

_, binary = cv2.threshold(crop, 128, 255, cv2.THRESH_BINARY)

# Find contours of white regions (rectangle borders)
contours, hierarchy = cv2.findContours(binary, cv2.RETR_CCOMP, cv2.CHAIN_APPROX_SIMPLE)

print(f"found {len(contours)} contours (hierarchy shape {None if hierarchy is None else hierarchy.shape})")

# RETR_CCOMP: top-level contours are outer boundaries; their children are holes.
# hierarchy[0][i] = [next, prev, first_child, parent]
# A rect has parent == -1 (top-level) and first_child != -1 (has an inner black hole).
rects = []
if hierarchy is not None:
    H_ = hierarchy[0]
    for i, c in enumerate(contours):
        nxt, prv, child, parent = H_[i]
        if parent != -1:
            continue  # inner contour, we'll match via child index
        x, y, w, h = cv2.boundingRect(c)
        if w < 8 or h < 8:
            continue  # skip tiny noise
        # get inner hole if present
        inner = None
        ci = child
        # pick largest child (the main inner hole)
        best = None
        while ci != -1:
            ix, iy, iw, ih = cv2.boundingRect(contours[ci])
            if best is None or iw*ih > best[2]*best[3]:
                best = (ix, iy, iw, ih)
            ci = H_[ci][0]  # next sibling
        if best:
            ix, iy, iw, ih = best
            rects.append({
                'x': x, 'y': y, 'w_out': w, 'h_out': h,
                'ix': ix, 'iy': iy, 'w_in': iw, 'h_in': ih,
                'tl': ix - x,  # left thickness
                'tr': (x + w) - (ix + iw),  # right thickness
                'tt': iy - y,  # top thickness
                'tb': (y + h) - (iy + ih),  # bottom thickness
            })

# Sort top-to-bottom, left-to-right (group by rows using y)
rects.sort(key=lambda r: (r['y'] // 20, r['x']))  # rough row grouping
# Re-group into rows properly: use y-median clustering
ys = sorted([r['y'] for r in rects])
# Simple row split: gap > ~30 pixels = new row
rows = [[]]
if rects:
    rects_by_y = sorted(rects, key=lambda r: r['y'])
    current_row_y = rects_by_y[0]['y']
    for r in rects_by_y:
        if r['y'] - current_row_y > 30:
            rows.append([])
            current_row_y = r['y']
        rows[-1].append(r)
# Sort each row left to right
for row in rows:
    row.sort(key=lambda r: r['x'])

print(f"\nRows: {len(rows)}, rects per row: {[len(r) for r in rows]}")
total = sum(len(r) for r in rows)
print(f"Total rects: {total}")

if total != 64:
    print("WARNING: Not 64 rectangles — extraction may be wrong")

# Flatten in reading order
ordered = [r for row in rows for r in row]

# Output table
print("\nIdx | out_w x out_h | in_w x in_h | t_L t_R t_T t_B")
print("-" * 64)
for i, r in enumerate(ordered):
    print(f"{i:3d} | {r['w_out']:3d}x{r['h_out']:3d} | {r['w_in']:3d}x{r['h_in']:3d} | {r['tl']:2d} {r['tr']:2d} {r['tt']:2d} {r['tb']:2d}")

# Compare to recorded RECT_DATA areas
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

print("\n\nCompare to repo data:")
print("Idx | img_out_area | repo_outer | img_in_area | repo_inner")
print("-" * 70)
for i, r in enumerate(ordered[:64] if len(ordered) >= 64 else ordered):
    img_out = r['w_out'] * r['h_out']
    img_in = r['w_in'] * r['h_in']
    if i < 64:
        ro, ri, rs = REPO[i]
        mark = '' if abs(img_out - ro) < 50 else ' !'
        print(f"{i:3d} | {img_out:5d} | {ro:5d} | {img_in:5d} | {ri:5d}{mark}")

# save results to json for downstream
import json
out = {'rects': ordered}
with open('/home/user/zden-puzzle/img/rects.json', 'w') as f:
    json.dump(out, f, indent=2)
print(f"\nSaved {len(ordered)} rectangles to rects.json")
