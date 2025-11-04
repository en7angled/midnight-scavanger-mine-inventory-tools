#!/usr/bin/env python3
"""
NIGHT Token Consolidation Script

This script consolidates NIGHT tokens from multiple addresses (from a JSON file)
into a single destination address using the Scavenger Mine API /donate_to endpoint.
"""

import argparse
import json
import urllib.parse
import requests
from typing import List, Optional
from pycardano import (
    Address,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    StakeSigningKey,
    StakeVerificationKey,
    HDWallet,
    VerificationKeyHash,
)


# Scavenger Mine API base URL
API_BASE_URL = "https://scavenger.prod.gd.midnighttge.io"


def derive_address_from_mnemonic(mnemonic: str, account: int, index: int = 0, network: Network = Network.TESTNET, use_cip1852: bool = True) -> tuple[str, PaymentSigningKey]:
    """
    Derive a Cardano address from a mnemonic phrase.
    
    Supports both CIP-1852 (modern wallets) and BIP44 (legacy).
    - CIP-1852: m/1852'/1815'/account'/0/index (default, used by Eternl, Daedalus, Yoroi)
    - BIP44: m/44'/1815'/account'/0/index (legacy)
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        account: Account number
        index: Address index within the account (default: 0)
        network: Cardano network (TESTNET or MAINNET)
        use_cip1852: If True, use CIP-1852 (default), if False, use BIP44
    
    Returns:
        Tuple of (address_string, signing_key)
    """
    # Use pycardano's HDWallet which properly handles CIP-1852
    wallet = HDWallet.from_mnemonic(mnemonic)
    
    if use_cip1852:
        # CIP-1852 derivation path: m/1852'/1815'/account'/0/index (payment)
        #                         m/1852'/1815'/account'/2/0 (stake)
        payment_path = f"m/1852'/1815'/{account}'/0/{index}"
        stake_path = f"m/1852'/1815'/{account}'/2/0"
    else:
        # BIP44 derivation path: m/44'/1815'/account'/0/index (payment)
        # For BIP44, we still need stake for base address, use same account
        payment_path = f"m/44'/1815'/{account}'/0/{index}"
        stake_path = f"m/44'/1815'/{account}'/2/0"
    
    # Derive payment and stake wallets
    payment_wallet = wallet.derive_from_path(payment_path, private=True)
    stake_wallet = wallet.derive_from_path(stake_path, private=True)
    
    # Extract private key for signing (xprivate_key is 64 bytes: chain code + private key)
    # Take the last 32 bytes which is the actual private key
    payment_private_key = payment_wallet.xprivate_key[32:] if len(payment_wallet.xprivate_key) >= 64 else payment_wallet.xprivate_key[:32]
    
    # Create signing key (needed for signing transactions)
    payment_signing_key = PaymentSigningKey.from_primitive(payment_private_key)
    
    # Create address hashes directly from public keys (Cardano uses blake2b-224)
    from hashlib import blake2b
    payment_hash = VerificationKeyHash(blake2b(payment_wallet.public_key, digest_size=28).digest())
    stake_hash = VerificationKeyHash(blake2b(stake_wallet.public_key, digest_size=28).digest())
    
    # Create base address with both payment and stake parts
    address = Address(
        payment_part=payment_hash,
        staking_part=stake_hash,
        network=network,
    )
    
    return str(address), payment_signing_key


def sign_message_cip30(message: str, signing_key: PaymentSigningKey) -> str:
    """
    Sign a message using CIP-30 signature format.
    
    CIP-30 uses Ed25519 signatures over UTF-8 encoded messages.
    
    Args:
        message: Message to sign
        signing_key: Payment signing key
    
    Returns:
        Hex-encoded signature string (128 characters, 64 bytes)
    """
    # Convert message to bytes (UTF-8 encoding)
    message_bytes = message.encode('utf-8')
    
    # Sign the message using Ed25519
    # pycardano's PaymentSigningKey uses Ed25519 internally
    signature = signing_key.sign(message_bytes)
    
    # Return hex-encoded signature
    # Ed25519 signatures are 64 bytes = 128 hex characters
    return signature.hex()


def get_donation_message(destination_address: str) -> str:
    """
    Get the message that needs to be signed for donation/consolidation.
    
    Args:
        destination_address: The destination address for consolidation
    
    Returns:
        Message string to sign
    """
    return f"Assign accumulated Scavenger rights to: {destination_address}"


def donate_to(
    original_address: str,
    destination_address: str,
    original_signing_key: PaymentSigningKey,
    destination_signing_key: PaymentSigningKey,
) -> dict:
    """
    Consolidate rewards from original_address to destination_address.
    
    Args:
        original_address: Source address to consolidate from
        destination_address: Destination address to consolidate to
        original_signing_key: Signing key for original address
        destination_signing_key: Signing key for destination address
    
    Returns:
        API response as dictionary with 'error' and 'statusCode' keys if error occurs
    """
    # Create the message to sign (must match exactly what API expects)
    message = get_donation_message(destination_address)
    
    # Sign with both keys
    signature_original = sign_message_cip30(message, original_signing_key)
    signature_destination = sign_message_cip30(message, destination_signing_key)
    
    # URL encode the addresses and signatures for the API endpoint
    original_encoded = urllib.parse.quote(original_address, safe='')
    destination_encoded = urllib.parse.quote(destination_address, safe='')
    
    # Construct the API endpoint
    url = f"{API_BASE_URL}/donate_to/{original_encoded}/{destination_encoded}/{signature_original}/{signature_destination}"
    
    # Make the API call
    try:
        response = requests.post(url, timeout=30)
        
        # Try to parse JSON response first
        try:
            response_data = response.json()
            # If status code indicates error, include it
            if response.status_code >= 400:
                response_data["statusCode"] = response.status_code
            return response_data
        except json.JSONDecodeError:
            # If not JSON, return text response
            return {
                "statusCode": response.status_code,
                "text": response.text,
                "error": f"HTTP {response.status_code}: {response.text[:200]}",
            }
    except requests.exceptions.HTTPError as e:
        # Try to get JSON error response
        try:
            if e.response:
                error_response = e.response.json()
                error_response["statusCode"] = e.response.status_code
                return error_response
        except:
            pass
        return {
            "error": str(e),
            "statusCode": e.response.status_code if e.response else None,
            "message": f"HTTP {e.response.status_code if e.response else 'Unknown'}: {str(e)}",
        }
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "statusCode": getattr(e.response, 'status_code', None) if hasattr(e, 'response') else None,
            "message": f"Request failed: {str(e)}",
        }


def load_addresses_from_json(json_path: str, mnemonic: str) -> tuple[dict, str, PaymentSigningKey]:
    """
    Load addresses from JSON file and derive signing keys from mnemonic.
    
    Args:
        json_path: Path to JSON file with address list
        mnemonic: BIP39 mnemonic phrase to derive signing keys
    
    Returns:
        Tuple of (address_data dict, destination_address, destination_signing_key)
    """
    with open(json_path, 'r') as f:
        address_data = json.load(f)
    
    # Determine network
    network_str = address_data.get("network", "testnet").lower()
    network = Network.MAINNET if network_str == "mainnet" else Network.TESTNET
    
    # Get destination info
    dest_info = address_data.get("destination", {})
    dest_account = dest_info.get("account", 0)
    dest_index = dest_info.get("index", 0)
    
    # Check if JSON specifies derivation method, default to CIP-1852
    use_cip1852 = address_data.get("use_cip1852", True)
    
    # Derive destination address and signing key
    destination_address, destination_signing_key = derive_address_from_mnemonic(
        mnemonic, dest_account, dest_index, network, use_cip1852
    )
    
    # Verify destination address matches
    expected_dest = dest_info.get("address")
    if expected_dest and destination_address != expected_dest:
        print(f"Warning: Derived destination address doesn't match JSON file!")
        print(f"  Expected: {expected_dest}")
        print(f"  Derived:  {destination_address}")
        print(f"  Using derived address...\n")
    
    return address_data, destination_address, destination_signing_key


def consolidate_addresses(
    json_path: str,
    mnemonic: str,
) -> None:
    """
    Consolidate NIGHT tokens from multiple addresses into one destination address.
    
    Args:
        json_path: Path to JSON file containing address list
        mnemonic: BIP39 mnemonic phrase to derive signing keys
    """
    print(f"Loading addresses from: {json_path}")
    
    # Load addresses and derive keys
    address_data, destination_address, destination_signing_key = load_addresses_from_json(
        json_path, mnemonic
    )
    
    network_str = address_data.get("network", "testnet")
    source_addresses = address_data.get("source_addresses", [])
    use_cip1852 = address_data.get("use_cip1852", True)  # Get derivation method from JSON
    
    print(f"Network: {network_str.upper()}")
    print(f"Destination address: {destination_address}")
    print(f"Source addresses to consolidate: {len(source_addresses)}\n")
    
    # Determine network for derivation
    network = Network.MAINNET if network_str == "mainnet" else Network.TESTNET
    
    # Consolidate each address
    successful = 0
    failed = 0
    skipped = 0
    
    for addr_info in source_addresses:
        address = addr_info.get("address")
        account = addr_info.get("account")
        index = addr_info.get("index")
        
        if not address:
            print(f"⚠️  Skipping entry with missing address: {addr_info}")
            skipped += 1
            continue
        
        # Skip if same as destination
        if address == destination_address:
            print(f"⚠️  Skipping address (same as destination): {address[:50]}...")
            skipped += 1
            continue
        
        # Derive signing key for this address
        try:
            if account is not None and index is not None:
                # Derive from account/index
                _, signing_key = derive_address_from_mnemonic(
                    mnemonic, account, index, network, use_cip1852
                )
                display_name = f"account {account}, index {index}"
            else:
                # If no account/index, we can't derive the key
                print(f"⚠️  Skipping {address[:50]}... (no account/index info)")
                skipped += 1
                continue
        except Exception as e:
            print(f"⚠️  Could not derive key for {address[:50]}...: {e}")
            skipped += 1
            continue
        
        print(f"Consolidating from {display_name}...")
        print(f"  Address: {address[:50]}...")
        
        try:
            result = donate_to(
                address,
                destination_address,
                signing_key,
                destination_signing_key,
            )
            
            if "error" in result or "statusCode" in result:
                status_code = result.get("statusCode")
                error_message = result.get("message", result.get("error", "Unknown error"))
                
                if status_code == 404:
                    print(f"  ⚠️  Address not registered (skipping)")
                    skipped += 1
                elif status_code == 409:
                    print(f"  ⚠️  {error_message}")
                    skipped += 1
                else:
                    print(f"  ❌ Error (Status {status_code}): {error_message}")
                    if "status_code" in result:
                        print(f"  Full response: {result}")
                    failed += 1
            else:
                print(f"  ✅ Successfully consolidated!")
                successful += 1
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            failed += 1
        
        print()
    
    print(f"\n{'='*60}")
    print(f"Consolidation complete!")
    print(f"  ✅ Successful: {successful}")
    print(f"  ⚠️  Skipped: {skipped}")
    print(f"  ❌ Failed: {failed}")
    print(f"  📊 Total processed: {len(source_addresses)}")
    print(f"Destination address: {destination_address}")
    print(f"{'='*60}")


def main():
    parser = argparse.ArgumentParser(
        description="Consolidate NIGHT tokens from multiple addresses into one",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Consolidate using addresses from JSON file
  python consolidate_night.py --addresses addresses.json --mnemonic "word1 word2 ... word24"
  
  # Generate addresses first, then consolidate
  python generate_addresses.py --mnemonic "word1 ... word24" --accounts 0 1 2 3 -o addresses.json
  python consolidate_night.py --addresses addresses.json --mnemonic "word1 ... word24"
        """
    )
    
    parser.add_argument(
        "--addresses",
        type=str,
        required=True,
        help="Path to JSON file containing address list (generated by generate_addresses.py)",
    )
    
    parser.add_argument(
        "--mnemonic",
        type=str,
        required=True,
        help="BIP39 mnemonic phrase (12 or 24 words) - used to derive signing keys",
    )
    
    args = parser.parse_args()
    
    # Validate mnemonic
    mnemonic_words = args.mnemonic.strip().split()
    if len(mnemonic_words) not in [12, 15, 18, 21, 24]:
        print("Error: Mnemonic must be 12, 15, 18, 21, or 24 words")
        return
    
    mnemonic = " ".join(mnemonic_words)
    
    # Run consolidation
    try:
        consolidate_addresses(
            json_path=args.addresses,
            mnemonic=mnemonic,
        )
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except FileNotFoundError:
        print(f"\n\nError: Address file not found: {args.addresses}")
        print("Generate it first using: python generate_addresses.py --help")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
