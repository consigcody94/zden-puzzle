"""
Extract exact rectangle dimensions from the puzzle image.
The WIDTH and HEIGHT of each rectangle (not just area) may be key.
"""
from PIL import Image
import numpy as np

img = Image.open('C:/Users/Public/crypto5fix.png')
pixels = np.array(img)

# Convert to binary (white=1, black=0)
binary = (pixels[:,:,0] > 128).astype(np.uint8)

print("Image size:", binary.shape)
print("Analyzing white rectangles...\n")

# Find connected components (rectangles)
from scipy import ndimage

# Label connected regions
labeled, num_features = ndimage.label(binary)
print(f"Found {num_features} connected white regions\n")

# Get properties of each region
regions = []
for i in range(1, num_features + 1):
    coords = np.where(labeled == i)
    if len(coords[0]) > 10:  # Ignore tiny specs
        min_y, max_y = coords[0].min(), coords[0].max()
        min_x, max_x = coords[1].min(), coords[1].max()
        height = max_y - min_y + 1
        width = max_x - min_x + 1
        area = len(coords[0])
        center_y = (min_y + max_y) // 2
        center_x = (min_x + max_x) // 2

        regions.append({
            'id': i,
            'x': min_x, 'y': min_y,
            'width': width, 'height': height,
            'area': area,
            'center': (center_x, center_y)
        })

# Sort by position (top to bottom, left to right)
regions.sort(key=lambda r: (r['y'] // 50, r['x']))

print("Rectangles found (sorted by position):")
print("-" * 70)

# Look for the 64 main rectangles (filter out the corner elements)
main_rects = []
for r in regions:
    # Main puzzle area is roughly in the center
    if 100 < r['x'] < 850 and 150 < r['y'] < 800:
        if r['area'] > 50:  # Substantial rectangles
            main_rects.append(r)

print(f"\nMain rectangles (likely the 64 puzzle elements): {len(main_rects)}")

# Sort into 8x8 grid
main_rects.sort(key=lambda r: (r['y'] // 80, r['x']))

# Print dimensions
print("\nRectangle dimensions (W x H):")
for i, r in enumerate(main_rects[:64]):
    if i % 8 == 0:
        print(f"\nRow {i//8}:", end=" ")
    print(f"{r['width']:3d}x{r['height']:<3d}", end=" ")

print("\n\n" + "="*70)
print("WIDTH and HEIGHT lists:")
print("="*70)

widths = [r['width'] for r in main_rects[:64]]
heights = [r['height'] for r in main_rects[:64]]

print(f"\nWidths: {widths}")
print(f"\nHeights: {heights}")

# Calculate areas from W*H
areas_calc = [w*h for w, h in zip(widths, heights)]
print(f"\nCalculated areas (W*H): {areas_calc}")

# Save for use in solver
import json
with open('C:/Users/Public/rect_dimensions.json', 'w') as f:
    json.dump({
        'widths': widths,
        'heights': heights,
        'areas': areas_calc,
        'rectangles': main_rects[:64]
    }, f, indent=2)

print("\nSaved to rect_dimensions.json")

# Check if widths/heights sum pairs could give 119
print("\n" + "="*70)
print("Checking for 0x77 (119) in width/height sums:")
print("="*70)

for i in range(len(widths)-1):
    for j in range(i+1, len(widths)):
        wsum = widths[i] + widths[j]
        hsum = heights[i] + heights[j]
        if wsum % 256 == 119 or wsum == 119:
            print(f"Width sum: rect[{i}] + rect[{j}] = {widths[i]} + {widths[j]} = {wsum}")
        if hsum % 256 == 119 or hsum == 119:
            print(f"Height sum: rect[{i}] + rect[{j}] = {heights[i]} + {heights[j]} = {hsum}")
