"""
Verify private keys against target Bitcoin address
"""
import hashlib
import ecdsa
import base58

TARGET = "1cryptoGeCRiTzVgxBQcKFFjSVydN1GW7"

def privkey_to_address(privkey_hex, compressed=True):
    """Convert private key hex to Bitcoin address"""
    try:
        # Get private key bytes
        privkey_bytes = bytes.fromhex(privkey_hex)

        # Create signing key
        sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
        vk = sk.get_verifying_key()

        if compressed:
            # Compressed public key
            if vk.pubkey.point.y() % 2 == 0:
                pubkey = b'\x02' + vk.to_string()[:32]
            else:
                pubkey = b'\x03' + vk.to_string()[:32]
        else:
            # Uncompressed public key
            pubkey = b'\x04' + vk.to_string()

        # SHA256 then RIPEMD160
        sha256_hash = hashlib.sha256(pubkey).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        pubkey_hash = ripemd160.digest()

        # Add version byte (0x00 for mainnet)
        versioned = b'\x00' + pubkey_hash

        # Double SHA256 for checksum
        checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]

        # Base58 encode
        address = base58.b58encode(versioned + checksum).decode()

        return address
    except Exception as e:
        return f"Error: {e}"

def check_key(privkey_hex, combo_name):
    """Check if a private key matches the target address"""
    addr_c = privkey_to_address(privkey_hex, compressed=True)
    addr_u = privkey_to_address(privkey_hex, compressed=False)

    match_c = addr_c == TARGET
    match_u = addr_u == TARGET

    if match_c or match_u:
        print(f"\n{'='*60}")
        print(f"MATCH FOUND! {combo_name}")
        print(f"Private Key: {privkey_hex}")
        print(f"Address (compressed): {addr_c} {'<-- MATCH!' if match_c else ''}")
        print(f"Address (uncompressed): {addr_u} {'<-- MATCH!' if match_u else ''}")
        print(f"{'='*60}\n")
        return True

    return False

# Read generated keys and verify
def main():
    print(f"Target address: {TARGET}")
    print("Verifying generated keys...\n")

    # Read keys from solver output
    try:
        with open("C:/Users/Public/zden_keys.txt", "r") as f:
            content = f.read()
    except:
        print("Running solver first...")
        import subprocess
        subprocess.run(["python", "C:/Users/Public/zden_lvl5_solver.py"])
        with open("C:/Users/Public/zden_keys.txt", "r") as f:
            content = f.read()

    # Parse keys
    lines = content.split('\n')
    current_combo = ""
    checked = 0

    for line in lines:
        if line.strip() and not line.startswith(' ') and not line.startswith('Target'):
            current_combo = line.strip()
        elif 'HEX:' in line:
            privkey = line.split('HEX:')[1].strip()
            if check_key(privkey, current_combo):
                return  # Found it!
            checked += 1

    print(f"\nChecked {checked} keys. No match found with standard approaches.")
    print("\nThe puzzle likely requires a different interpretation:")
    print("1. Different pairing pattern (strikethrough hint)")
    print("2. Different normalization formula")
    print("3. The mini-puzzle '09111819 FIN 11122111' encodes the solution")

if __name__ == "__main__":
    main()
