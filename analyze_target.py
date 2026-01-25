"""
Analyze the target address for patterns.
"""
import hashlib
import base58

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

print("="*70)
print("TARGET ADDRESS ANALYSIS")
print("="*70)

# Decode the address
decoded = base58.b58decode(TARGET)
print(f"Address: {TARGET}")
print(f"Decoded hex: {decoded.hex()}")
print(f"Length: {len(decoded)} bytes")

# Extract components
version = decoded[0]
hash160 = decoded[1:21]
checksum = decoded[21:]

print(f"\nVersion byte: {version} (0x{version:02x})")
print(f"Hash160: {hash160.hex()}")
print(f"Checksum: {checksum.hex()}")

# Analyze the hash160
print("\n" + "-"*50)
print("Hash160 Analysis")
print("-"*50)

h = hash160
print(f"As bytes: {list(h)}")
print(f"First byte: {h[0]} (0x{h[0]:02x})")
print(f"Sum of all bytes: {sum(h)}")

# Look for patterns
print("\nByte value distribution:")
for i, b in enumerate(h):
    print(f"  Byte {i:2d}: {b:3d} (0x{b:02x})")

# Check if any bytes are 0x28 or 0x77
print(f"\n0x28 (40) in hash160: {0x28 in h}")
print(f"0x77 (119) in hash160: {0x77 in h}")

# Check for any relationship with our puzzle numbers
print("\n" + "-"*50)
print("Looking for puzzle number patterns")
print("-"*50)

puzzle_numbers = [7, 10, 17, 30, 39, 40, 52, 64, 119]
for num in puzzle_numbers:
    positions = [i for i, b in enumerate(h) if b == num]
    if positions:
        print(f"  {num} found at positions: {positions}")

# XOR analysis
print("\n" + "-"*50)
print("XOR patterns with hash160")
print("-"*50)

# What XOR key would turn hash160 into something meaningful?
# hash160[0] = 0x06, we want first byte 0x28
# 0x06 ^ X = 0x28 -> X = 0x2E
print(f"XOR to get 0x28 from first byte: 0x{h[0] ^ 0x28:02x}")

# Try XOR with our base key
shell = [
    2484, 1384, 1072, 1256, 1230, 958, 732, 1260,
    434, 300, 334, 950, 182, 298, 1836, 1118,
    1488, 938, 786, 582, 468, 816, 1400, 1770,
    1390, 1186, 1828, 1228, 1284, 1780, 1668, 1692,
    608, 586, 808, 666, 1240, 1218, 912, 839,
    660, 458, 1120, 1134, 448, 1050, 780, 1054,
    1470, 832, 954, 1238, 118, 88, 1402, 1868,
    1642, 282, 912, 1598, 368, 1520, 1000, 656
]

shell_m = shell.copy()
shell_m[39] *= 17

base_key = [(shell_m[i*2] + shell_m[i*2+1]) // 7 % 256 for i in range(32)]

# Compare base key with extended hash160
print("\nComparing base key with hash160 (first 20 bytes):")
for i in range(20):
    diff = base_key[i] ^ h[i]
    print(f"  Pos {i:2d}: base={base_key[i]:3d} h160={h[i]:3d} XOR={diff:3d} (0x{diff:02x})")

# What transformation would turn base_key[:20] into hash160?
print("\n" + "-"*50)
print("Transformation analysis")
print("-"*50)

# Check if there's a simple relationship
diff_sum = sum(base_key[i] - h[i] for i in range(20))
xor_sum = sum(base_key[i] ^ h[i] for i in range(20))
print(f"Sum of differences (base - h160): {diff_sum}")
print(f"Sum of XOR values: {xor_sum}")

# Check if shifting the key helps
for shift in range(32):
    shifted = base_key[shift:] + base_key[:shift]
    match_count = sum(1 for i in range(20) if shifted[i] == h[i])
    if match_count > 0:
        print(f"Shift {shift}: {match_count} byte matches with hash160")

print("\n" + "="*70)
print("Analysis complete")
print("="*70)
