"""
Verify the base calculation and try systematic variations.

We know:
- (shell[0] + shell[1]) / 7 % 256 = 40 = 0x28 ✓
- (shell[38] + shell[39]*17) / 7 % 256 = 119 = 0x77 ✓

The key 284c381c68b744a65ac3b7c470b4b5e0aad25f779f42d60648391dd312660dec
gives address 1B2aZ783P4943rwmXhcDjye3hPJi2FaJSh
but we need 1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7

Something is still off. Let's try:
1. Different multiplier values
2. Different divisor values
3. Different positions for the multiplier
4. Maybe the 17px is not a multiplier but something else
"""
import hashlib
import ecdsa
import base58

RECT_DATA = [
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

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

shell = [r[2] for r in RECT_DATA]
outer = [r[0] for r in RECT_DATA]
inner = [r[1] for r in RECT_DATA]

def privkey_to_address(privkey_bytes, compressed=True):
    try:
        sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()
        if compressed:
            if vk.pubkey.point.y() % 2 == 0:
                pubkey = b'\x02' + vk.to_string()[:32]
            else:
                pubkey = b'\x03' + vk.to_string()[:32]
        else:
            pubkey = b'\x04' + vk.to_string()
        sha256_hash = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()
        versioned = b'\x00' + pubkey_hash
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
        return base58.b58encode(versioned + checksum).decode()
    except:
        return None

def check_key(byte_list, desc=""):
    if len(byte_list) != 32:
        return False
    if not all(0 <= b <= 255 for b in byte_list):
        return False
    privkey_bytes = bytes(byte_list)
    for compressed in [True, False]:
        addr = privkey_to_address(privkey_bytes, compressed)
        if addr == TARGET:
            print(f"\n{'='*60}")
            print(f"SOLVED! {desc}")
            print(f"Key: {privkey_bytes.hex()}")
            print(f"Compressed: {compressed}")
            print(f"{'='*60}")
            with open("C:/Users/Public/SOLUTION.txt", "w") as f:
                f.write(f"Solution: {desc}\n")
                f.write(f"Key: {privkey_bytes.hex()}\n")
            return True
    return False

print("="*70)
print("VERIFICATION AND SYSTEMATIC SEARCH")
print("="*70)

# ============================================================================
# 1. Verify base calculation
# ============================================================================
print("\n[1] Verifying base calculation...")

print(f"shell[0] = {shell[0]}, shell[1] = {shell[1]}")
print(f"(shell[0] + shell[1]) / 7 = {(shell[0] + shell[1]) // 7}")
print(f"That mod 256 = {(shell[0] + shell[1]) // 7 % 256} (should be 40 = 0x28)")

print(f"\nshell[38] = {shell[38]}, shell[39] = {shell[39]}")
print(f"(shell[38] + shell[39]*17) / 7 = {(shell[38] + shell[39]*17) // 7}")
print(f"That mod 256 = {(shell[38] + shell[39]*17) // 7 % 256} (should be 119 = 0x77)")

# ============================================================================
# 2. Try WITHOUT the multiplier at 39
# ============================================================================
print("\n[2] Without multiplier at 39...")

for div in [7, 10, 17]:
    pairs = []
    for i in range(32):
        val = (shell[i*2] + shell[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    print(f"  No mult, div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
    if check_key(pairs, f"nomult_div{div}"):
        exit()

# ============================================================================
# 3. Try all multipliers 1-100 at position 39
# ============================================================================
print("\n[3] Brute force multiplier at 39...")

for mult in range(1, 101):
    shell_m = shell.copy()
    shell_m[39] *= mult

    for div in [7, 10]:
        pairs = []
        for i in range(32):
            val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
            pairs.append(val)

        if check_key(pairs, f"mult{mult}_div{div}"):
            exit()

print("  Multipliers 1-100: no solution")

# ============================================================================
# 4. Try multiplier at different positions
# ============================================================================
print("\n[4] Multiplier at different positions...")

for pos in range(64):
    for mult in [7, 17]:
        shell_m = shell.copy()
        shell_m[pos] *= mult

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            if check_key(pairs, f"pos{pos}_mult{mult}_div{div}"):
                exit()

print("  Different positions: no solution")

# ============================================================================
# 5. Maybe the 17 is added, not multiplied?
# ============================================================================
print("\n[5] Adding instead of multiplying...")

for pos in [39, 52]:
    for add_val in [17, 119, 40, 64]:
        shell_m = shell.copy()
        shell_m[pos] += add_val

        for div in [7, 10]:
            pairs = []
            for i in range(32):
                val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                pairs.append(val)

            has_77 = [j for j,p in enumerate(pairs) if p==0x77]
            if has_77 and pairs[0] == 0x28:
                print(f"  pos{pos} + {add_val} div{div}: first={hex(pairs[0])}, 0x77 at {has_77}")
                if check_key(pairs, f"add{add_val}_pos{pos}_div{div}"):
                    exit()

# ============================================================================
# 6. What if we need to use outer and inner, not shell?
# ============================================================================
print("\n[6] Using outer and inner values...")

# outer - inner = shell, so try other combinations
for div in [7, 10, 17]:
    # outer alone
    pairs = []
    for i in range(32):
        val = (outer[i*2] + outer[i*2+1]) // div % 256
        pairs.append(val)
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Outer div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"outer_div{div}"):
            exit()

    # inner alone
    pairs = []
    for i in range(32):
        val = (inner[i*2] + inner[i*2+1]) // div % 256
        pairs.append(val)
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Inner div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"inner_div{div}"):
            exit()

    # outer + inner
    pairs = []
    for i in range(32):
        val = (outer[i*2] + outer[i*2+1] + inner[i*2] + inner[i*2+1]) // div % 256
        pairs.append(val)
    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Outer+Inner div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"outer_inner_div{div}"):
            exit()

# ============================================================================
# 7. What if the key needs byte swapping or endianness change?
# ============================================================================
print("\n[7] Endianness and byte swapping...")

shell_m = shell.copy()
shell_m[39] *= 17

base = []
for i in range(32):
    val = (shell_m[i*2] + shell_m[i*2+1]) // 7 % 256
    base.append(val)

# Reverse byte order
pairs = base[::-1]
if check_key(pairs, "reversed"):
    exit()

# Swap pairs
pairs = []
for i in range(0, 32, 2):
    pairs.append(base[i+1] if i+1 < 32 else base[i])
    pairs.append(base[i])
if check_key(pairs, "pair_swapped"):
    exit()

# Swap 4-byte groups (like little/big endian integers)
pairs = []
for i in range(0, 32, 4):
    for j in [3, 2, 1, 0]:
        if i+j < 32:
            pairs.append(base[i+j])
if len(pairs) == 32:
    if check_key(pairs, "int32_swapped"):
        exit()

# ============================================================================
# 8. What if we misinterpreted and 17 is a divisor or the position?
# ============================================================================
print("\n[8] 17 as divisor or position...")

# 17 as divisor
for mult in [1, 7]:
    shell_m = shell.copy()
    shell_m[39] *= mult

    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1]) // 17 % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  Mult{mult} div17: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"mult{mult}_div17"):
            exit()

# 17 as position to multiply
shell_m = shell.copy()
shell_m[17] *= 7  # Or some other multiplier

for div in [7, 10]:
    pairs = []
    for i in range(32):
        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  pos17*7 div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"pos17_mult7_div{div}"):
            exit()

# ============================================================================
# 9. What if there are TWO multipliers?
# ============================================================================
print("\n[9] Two multipliers search...")

for p1 in [17, 39, 52]:
    for p2 in [17, 39, 52]:
        if p1 >= p2:
            continue
        for m1 in [7, 17]:
            for m2 in [6, 7, 17]:
                shell_m = shell.copy()
                shell_m[p1] *= m1
                shell_m[p2] *= m2

                for div in [7, 10]:
                    pairs = []
                    for i in range(32):
                        val = (shell_m[i*2] + shell_m[i*2+1]) // div % 256
                        pairs.append(val)

                    if check_key(pairs, f"p{p1}m{m1}_p{p2}m{m2}_div{div}"):
                        exit()

print("  Two multipliers: no solution")

# ============================================================================
# 10. What about the formula -I *X+ LXIV /x/?
#     Maybe: subtract 1, multiply by 10, add 64, divide by 10
# ============================================================================
print("\n[10] Roman numeral formula variations...")

shell_m = shell.copy()
shell_m[39] *= 17

for formula_id, formula_func in [
    ("(s-1)*10+64)/10", lambda s: ((s - 1) * 10 + 64) // 10),
    ("s*10//64", lambda s: s * 10 // 64),
    ("(s+64)//10", lambda s: (s + 64) // 10),
    ("(s-64)//7", lambda s: (s - 64) // 7),
    ("s//10+64//10", lambda s: s // 10 + 64 // 10),
]:
    pairs = []
    for i in range(32):
        s = shell_m[i*2] + shell_m[i*2+1]
        val = formula_func(s) % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77 or pairs[0] == 0x28:
        print(f"  {formula_id}: first={hex(pairs[0])}, 0x77 at {has_77}")
        if check_key(pairs, f"formula_{formula_id[:10]}"):
            exit()

# ============================================================================
# 11. What if the mini-puzzle tells us to XOR specific positions?
# ============================================================================
print("\n[11] XOR at positions from mini-puzzle...")

positions = [9, 11, 18, 19, 11, 12, 21, 11]

for xor_val in [0x28, 0x77, 39, 57, 17]:
    pairs = base.copy()
    for pos in positions:
        if pos < 32:
            pairs[pos] ^= xor_val

    if check_key(pairs, f"xor_positions_{xor_val}"):
        exit()

# ============================================================================
# 12. Maybe use the actual rectangle pixel dimensions?
# ============================================================================
print("\n[12] Using original dimensions...")

# The "17px thick" line might mean we should look at raw pixel values
# RECT_DATA has (outer_area, inner_area, shell_area)
# But these are areas, not dimensions

# What if shell values need to be square-rooted (to get dimension)?
import math

for div in [1, 7, 10]:
    pairs = []
    for i in range(32):
        s1 = int(math.sqrt(shell[i*2]))
        s2 = int(math.sqrt(shell[i*2+1]))
        val = (s1 + s2) // div % 256 if div > 1 else (s1 + s2) % 256
        pairs.append(val)

    has_77 = [j for j,p in enumerate(pairs) if p==0x77]
    if has_77:
        print(f"  Sqrt div{div}: 0x77 at {has_77}")
        if check_key(pairs, f"sqrt_div{div}"):
            exit()

print("\n" + "="*70)
print("Systematic search complete, no solution found")
print("="*70)

# Print current best
print(f"\nCurrent best key:")
print(f"Hex: {bytes(base).hex()}")
print(f"Address: {privkey_to_address(bytes(base), True)}")
print(f"Target:  {TARGET}")
