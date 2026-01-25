"""
Estimate search time for brute force
"""
import time
import hashlib
import ecdsa
import base58

# Benchmark ECDSA operations (the bottleneck)
print("Benchmarking ECDSA address derivation...")

def derive_address(privkey_bytes):
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey = b'\x02' + vk.to_string()[:32]
    sha256_hash = hashlib.sha256(pubkey).digest()
    ripemd160 = hashlib.new('ripemd160')
    ripemd160.update(sha256_hash)
    pubkey_hash = ripemd160.digest()
    versioned = b'\x00' + pubkey_hash
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58.b58encode(versioned + checksum).decode()

# Benchmark
test_key = bytes(range(32))
start = time.time()
iterations = 100
for _ in range(iterations):
    derive_address(test_key)
elapsed = time.time() - start

derivations_per_sec = iterations / elapsed
print(f"ECDSA derivations per second: {derivations_per_sec:.0f}")
print()

# Search space analysis
print("="*60)
print("SEARCH SPACE ANALYSIS")
print("="*60)

pairing_patterns = 30  # Different ways to pair rectangles
divisors = 256  # Possible divisors (1-256)
mult40_options = 3  # 1, 7, 17
mult53_options = 3  # 1, 6, 7
area_types = 3  # shell, outer, inner
xor_operations = 10  # XOR variants

# Basic search
basic_combinations = pairing_patterns * divisors * mult40_options * mult53_options * area_types
print(f"Basic (sum/div) combinations: {basic_combinations:,}")

# Extended search
extended_combinations = basic_combinations + (pairing_patterns * xor_operations * mult40_options * mult53_options * area_types)
print(f"Extended (+ XOR) combinations: {extended_combinations:,}")

# If we try all possible pairing permutations (much larger)
# For 64 rectangles into 32 pairs: this is astronomical
# But with constraints, we only try structured patterns

# Estimate how many pass the "contains 119" filter
# Roughly 1-5% of combinations will have 119 somewhere in 32 bytes
filter_rate = 0.03  # 3% estimate

candidates_to_check = int(extended_combinations * filter_rate)
print(f"Estimated candidates with 0x77: {candidates_to_check:,}")

print()
print("="*60)
print("TIME ESTIMATES")
print("="*60)

# CPU time
cpu_cores = 8  # Typical
cpu_rate = derivations_per_sec * cpu_cores
cpu_time_basic = basic_combinations * filter_rate / cpu_rate
cpu_time_extended = extended_combinations * filter_rate / cpu_rate

print(f"\nCPU ({cpu_cores} cores @ {derivations_per_sec:.0f}/sec each):")
print(f"  Basic search: {cpu_time_basic:.1f} seconds ({cpu_time_basic/60:.1f} minutes)")
print(f"  Extended search: {cpu_time_extended:.1f} seconds ({cpu_time_extended/60:.1f} minutes)")

# GPU time (estimate: 100-500x faster for ECDSA)
gpu_speedup = 200  # Conservative estimate
gpu_time_basic = cpu_time_basic / gpu_speedup
gpu_time_extended = cpu_time_extended / gpu_speedup

print(f"\nGPU (estimated {gpu_speedup}x faster):")
print(f"  Basic search: {gpu_time_basic:.2f} seconds")
print(f"  Extended search: {gpu_time_extended:.2f} seconds")

# If we try truly exhaustive pairing (all permutations)
print()
print("="*60)
print("EXHAUSTIVE PAIRING SEARCH (if needed)")
print("="*60)

# For a more thorough search trying random/heuristic pairings
random_pairings = 1000000  # 1M random pairing attempts
exhaustive_cpu_time = random_pairings * filter_rate / cpu_rate
exhaustive_gpu_time = exhaustive_cpu_time / gpu_speedup

print(f"1M random pairings:")
print(f"  CPU: {exhaustive_cpu_time/60:.1f} minutes")
print(f"  GPU: {exhaustive_gpu_time:.1f} seconds")

print()
print("="*60)
print("RECOMMENDATION")
print("="*60)
print("""
The structured search (pairing patterns + operations) is fast
and should complete in under a minute on CPU.

If the solution requires a non-obvious pairing pattern,
GPU would help explore larger spaces quickly.

Let me run the CPU search now...
""")
