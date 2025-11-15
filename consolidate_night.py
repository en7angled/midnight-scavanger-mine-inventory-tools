#!/usr/bin/env python3
"""
NIGHT Token Consolidation Script

This script consolidates NIGHT tokens from multiple addresses into a single destination 
address using the Scavenger Mine API /donate_to endpoint.

It processes addresses from an allocation report and generates a detailed consolidation report.
"""

import argparse
import json
import urllib.parse
import requests
import time
from datetime import datetime
from collections import defaultdict
from typing import Optional
from pycardano import (
    Address,
    Network,
    PaymentSigningKey,
    HDWallet,
    VerificationKeyHash,
)
# Scavenger Mine API base URL
API_BASE_URL = "https://scavenger.prod.gd.midnighttge.io"


def derive_address_from_mnemonic(mnemonic: str, account: int, index: int = 0, network: Network = Network.TESTNET, use_cip1852: bool = True, staked: bool = True) -> tuple[str, PaymentSigningKey, bytes]:
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
        staked: If True, generate base address (addr1q) with stake, if False, generate enterprise address (addr1v) without stake
    
    Returns:
        Tuple of (address_string, signing_key, public_key_bytes)
    """
    # Use pycardano's HDWallet which properly handles CIP-1852
    wallet = HDWallet.from_mnemonic(mnemonic)
    
    if use_cip1852:
        # CIP-1852 derivation path: m/1852'/1815'/account'/0/index (payment)
        payment_path = f"m/1852'/1815'/{account}'/0/{index}"
        if staked:
            # For staked addresses, we need stake path: m/1852'/1815'/account'/2/0
            stake_path = f"m/1852'/1815'/{account}'/2/0"
    else:
        # BIP44 derivation path: m/44'/1815'/account'/0/index (payment)
        payment_path = f"m/44'/1815'/{account}'/0/{index}"
        if staked:
            # For staked addresses, we need stake path: m/44'/1815'/account'/2/0
            stake_path = f"m/44'/1815'/{account}'/2/0"
    
    # Derive payment wallet
    payment_wallet = wallet.derive_from_path(payment_path, private=True)
    
    # Derive stake wallet only if needed for staked addresses
    if staked:
        stake_wallet = wallet.derive_from_path(stake_path, private=True)
    
    # Extract private key for signing
    # pycardano's HDWallet uses BIP32 Ed25519 where xprivate_key is kL + kR (64 bytes)
    # - kL (first 32 bytes): private scalar used to compute the public key
    # - kR (last 32 bytes): used for signing
    # We use kL (first 32 bytes) for PaymentSigningKey compatibility
    payment_private_key = payment_wallet.xprivate_key[:32] if len(payment_wallet.xprivate_key) >= 32 else payment_wallet.xprivate_key
    
    # Create PaymentSigningKey from kL (for compatibility with existing code)
    payment_signing_key = PaymentSigningKey.from_primitive(payment_private_key)
    
    # Store the full xprivate_key (kL + kR, 64 bytes) and chain_code for BIP32 Ed25519 signing
    # This allows us to use BIP32ED25519PrivateKey for proper signing that matches the wallet's public key
    payment_signing_key._wallet_xprivate_key = payment_wallet.xprivate_key  # kL + kR (64 bytes)
    payment_signing_key._wallet_chain_code = payment_wallet.chain_code  # chain code (32 bytes)
    payment_signing_key._wallet_public_key = payment_wallet.public_key  # public key (32 bytes, matches address)
    
    # Create address hashes directly from public keys (Cardano uses blake2b-224)
    from hashlib import blake2b
    payment_hash = VerificationKeyHash(blake2b(payment_wallet.public_key, digest_size=28).digest())
    
    if staked:
        stake_hash = VerificationKeyHash(blake2b(stake_wallet.public_key, digest_size=28).digest())
        # Create base address with both payment and stake parts (addr1q)
        address = Address(
            payment_part=payment_hash,
            staking_part=stake_hash,
            network=network,
        )
    else:
        # Create enterprise address without stake part (addr1v)
        address = Address(
            payment_part=payment_hash,
            network=network,
        )
    
    # Return address, signing key, and the public key bytes (32 bytes)
    # The wallet's public_key is what was used to create the address (matches Eternl)
    public_key_bytes = payment_wallet.public_key
    
    return str(address), payment_signing_key, public_key_bytes


def sign_message_cip30(message: str, signing_key: PaymentSigningKey, address: Optional[str] = None, use_cbor: bool = True) -> str:
    """
    Sign a message using CIP-30 signature format.
    
    CIP-30 signature can be either:
    - Raw hex (for donation endpoint): Just the Ed25519 signature hex
    - CBOR-encoded (for registration): CBOR structure with signature, key, and message
    
    Args:
        message: Message to sign
        signing_key: Payment signing key
        address: Optional address (required for CBOR format)
        use_cbor: If True, return CBOR-encoded format; if False, return raw hex
    
    Returns:
        Hex-encoded signature string (CBOR if use_cbor=True, raw hex if False)
    """
    # Convert message to bytes (UTF-8 encoding)
    message_bytes = message.encode('utf-8')
    
    # Use BIP32ED25519PrivateKey for signing (same as registration)
    # This ensures the signature can be verified with the wallet's public key
    from pycardano.crypto.bip32 import BIP32ED25519PrivateKey
    
    # Check if we have the full xprivate_key and chain_code stored (from derive_address_from_mnemonic)
    wallet_xprivate_key = getattr(signing_key, '_wallet_xprivate_key', None)
    wallet_chain_code = getattr(signing_key, '_wallet_chain_code', None)
    
    if wallet_xprivate_key and wallet_chain_code and len(wallet_xprivate_key) == 64:
        # Use BIP32ED25519PrivateKey for proper BIP32 Ed25519 signing
        bip32_private_key = BIP32ED25519PrivateKey(
            private_key=wallet_xprivate_key,  # kL + kR (64 bytes)
            chain_code=wallet_chain_code
        )
        # Sign with BIP32 Ed25519 (returns 64-byte signature)
        signature_bytes = bip32_private_key.sign(message_bytes)
        
        # If not using CBOR, return raw hex signature (for donation endpoint)
        if not use_cbor:
            return signature_bytes.hex()
    else:
        # Fallback to pycardano signing (might not work correctly)
        # This should only happen if the signing key wasn't created via derive_address_from_mnemonic
        signature_bytes = signing_key.sign(message_bytes)
        if not use_cbor:
            return signature_bytes.hex()
    
    # For CBOR format (registration endpoint), we need the address
    import cbor2
    from pycardano import Address
    
    if not address:
        # Derive address from verification key
        from pycardano import PaymentVerificationKey, VerificationKeyHash
        from hashlib import blake2b
        verification_key = signing_key.to_verification_key()
        payment_hash = VerificationKeyHash(blake2b(bytes(verification_key), digest_size=28).digest())
        # For registration, we might not have stake key, so create enterprise address
        try:
            address_obj = Address(payment_part=payment_hash, network=Network.MAINNET)
            address = str(address_obj)
        except:
            # Fallback: use the hash directly
            address = payment_hash.to_primitive().hex()
    
    # CIP-8/CIP-30 signature structure (COSE Sign1 format):
    # Based on the working Rust implementation in shadowharvester:
    # 
    # Step 1: Create protected header (CBOR map):
    #   Key 1: -8 (algorithm identifier for Ed25519)
    #   Key "address": address bytes
    #
    # Step 2: Create CoseSignData structure to sign:
    #   Array of 4: ["Signature1", protected_header_cbor, external_aad (empty), payload]
    #
    # Step 3: Sign the CoseSignData CBOR (not just the message!)
    #
    # Step 4: Create final COSE Sign1 structure:
    #   Array of 4:
    #     [0] protected_header (CBOR bytes)
    #     [1] unprotected_header (CBOR map with "hashed": false)
    #     [2] payload (message bytes)
    #     [3] signature (64 bytes Ed25519 signature)
    
    # Parse the address to get its bytes
    # The address needs to be converted to its raw bytes representation
    # In Rust: kp.2.to_vec() where kp.2 is a ShelleyAddress
    # This gets the address as a byte vector (the raw address bytes)
    try:
        # Decode the Bech32 address to get the Address object
        addr_obj = Address.decode(address)
        # Get the address as bytes (this should match kp.2.to_vec() in Rust)
        address_bytes = bytes(addr_obj)
    except Exception as e:
        # If decoding fails, try alternative method
        try:
            # Try using the address's payment part hash
            from pycardano import PaymentVerificationKey, VerificationKeyHash
            from hashlib import blake2b
            verification_key = signing_key.to_verification_key()
            payment_hash = VerificationKeyHash(blake2b(bytes(verification_key), digest_size=28).digest())
            # Use the hash as address bytes (this might not be correct, but it's a fallback)
            address_bytes = payment_hash.to_primitive()
        except:
            # Last resort: encode address string as UTF-8 (not ideal, but better than failing)
            address_bytes = address.encode('utf-8')
    
    # Step 1: Create protected header: CBOR map with algorithm (-8) and address
    protected_header = {
        1: -8,  # Algorithm identifier for Ed25519
        "address": address_bytes
    }
    protected_header_cbor = cbor2.dumps(protected_header)
    
    # Step 2: Create CoseSignData structure (this is what we sign)
    # Array of 4: ["Signature1", protected_header_cbor, external_aad, payload]
    cose_sign_data = [
        "Signature1",           # Label
        protected_header_cbor,  # Protected header (CBOR bytes)
        b"",                    # External AAD (empty)
        message_bytes           # Payload (message bytes)
    ]
    to_sign_cbor = cbor2.dumps(cose_sign_data)
    
    # Step 3: Sign the CoseSignData CBOR (not just the message!)
    # Use BIP32ED25519PrivateKey for signing (same approach as donation)
    if wallet_xprivate_key and wallet_chain_code and len(wallet_xprivate_key) == 64:
        # Use BIP32ED25519PrivateKey for proper BIP32 Ed25519 signing
        # This ensures the signature can be verified with the wallet's public key
        bip32_private_key = BIP32ED25519PrivateKey(
            private_key=wallet_xprivate_key,  # kL + kR (64 bytes)
            chain_code=wallet_chain_code
        )
        # Sign the CoseSignData CBOR (not just the message!)
        signature_bytes = bip32_private_key.sign(to_sign_cbor)
    else:
        # Fallback to nacl signing (standard Ed25519, not BIP32)
        # This should only happen if the signing key wasn't created via derive_address_from_mnemonic
        import nacl.signing
        signing_key_bytes = bytes(signing_key)
        if len(signing_key_bytes) >= 32:
            private_key = signing_key_bytes[:32]
        else:
            private_key = signing_key_bytes
        nacl_signing_key = nacl.signing.SigningKey(private_key)
        signed_message = nacl_signing_key.sign(to_sign_cbor)
        signature_bytes = signed_message.signature  # Extract just the signature (64 bytes)
    
    # Step 4: Create unprotected header: CBOR map with "hashed": false
    unprotected_header = {
        "hashed": False
    }
    
    # Step 5: Create final COSE Sign1 structure: [protected_header, unprotected_header, payload, signature]
    cose_sign1 = [
        protected_header_cbor,  # Element 0: Protected header (CBOR bytes)
        unprotected_header,     # Element 1: Unprotected header (CBOR map)
        message_bytes,          # Element 2: Payload (message bytes)
        signature_bytes         # Element 3: Signature (64 bytes)
    ]
    
    cbor_bytes = cbor2.dumps(cose_sign1)
    
    # Return hex-encoded CBOR
    return cbor_bytes.hex()






def get_donation_message(destination_address: str) -> str:
    """
    Get the message that needs to be signed for donation/consolidation.
    
    According to the API error messages, the message format is:
    "Assign accumulated Scavenger rights to: {destination_address}"
    
    Args:
        destination_address: The destination address for consolidation
    
    Returns:
        Message string to sign: "Assign accumulated Scavenger rights to: {destination_address}"
    """
    return f"Assign accumulated Scavenger rights to: {destination_address}"


def generate_consolidation_command(
    original_address: str,
    destination_address: str,
    original_signing_key: PaymentSigningKey,
    destination_signing_key: PaymentSigningKey,
) -> str:
    """
    Generate a curl command for consolidating rewards from original_address to destination_address.
    
    This function generates the command but does NOT execute it.
    
    Args:
        original_address: Source address to consolidate from
        destination_address: Destination address to consolidate to
        original_signing_key: Signing key for original address
        destination_signing_key: Signing key for destination address (not used, kept for compatibility)
    
    Returns:
        curl command string ready to execute
    """
    # Create the message to sign (must match exactly what API expects)
    # Message format: "Assign accumulated Scavenger rights to: {destination_address}"
    message = get_donation_message(destination_address)
    
    # Sign with the original address key only (per API docs)
    # For donation endpoint, use COSE_Sign1 format (CBOR) - API requires this format
    signature_original = sign_message_cip30(message, original_signing_key, original_address, use_cbor=True)
    
    # URL encode the addresses and signature for the API endpoint
    # Cardano addresses use base58 which is URL-safe, but encode to be safe
    # Signatures are hex (0-9, a-f) which are URL-safe, but encode to be safe
    original_encoded = urllib.parse.quote(original_address, safe='')
    destination_encoded = urllib.parse.quote(destination_address, safe='')
    signature_encoded = urllib.parse.quote(signature_original, safe='')
    
    # Construct the API endpoint per API docs: /donate_to/{destination}/{original}/{signature}
    url = f"{API_BASE_URL}/donate_to/{destination_encoded}/{original_encoded}/{signature_encoded}"
    
    # Generate curl command
    curl_command = f"curl -X POST '{url}'"
    
    return curl_command


def load_allocation_report(
    json_path: str, 
    mnemonic: str,
    destination_mnemonic: Optional[str] = None,
    destination_account: Optional[int] = None,
    destination_index: Optional[int] = None,
) -> tuple[dict, str, PaymentSigningKey]:
    """
    Load allocation report and derive destination signing key.
    
    Args:
        json_path: Path to allocation report JSON file (from check_all_allocations.py)
        mnemonic: BIP39 mnemonic phrase to derive source address signing keys
        destination_mnemonic: Optional BIP39 mnemonic phrase for destination (if different from source)
        destination_account: Optional account number to override destination from report
        destination_index: Optional index to override destination from report
    
    Returns:
        Tuple of (address_data dict, destination_address, destination_signing_key)
    """
    with open(json_path, 'r') as f:
        address_data = json.load(f)
    
    # Verify this is an allocation report format
    if "metadata" not in address_data or "addresses" not in address_data:
        raise ValueError(
            "File does not appear to be an allocation report. "
            "Expected format with 'metadata' and 'addresses' keys. "
            "Please use a report generated by check_all_allocations.py"
        )
    
    # Allocation report format
    metadata = address_data.get("metadata", {})
    network_str = metadata.get("network", "MAINNET").lower()
    network = Network.MAINNET if network_str == "mainnet" else Network.TESTNET
    use_cip1852 = True  # Default to CIP-1852
    
    # Determine which mnemonic to use for destination
    dest_mnemonic = destination_mnemonic if destination_mnemonic else mnemonic
    
    # Determine destination
    if destination_account is not None and destination_index is not None:
        # Use provided account/index to override report
        dest_account = destination_account
        dest_index = destination_index
        
        # Try to determine if staked from report, otherwise default to staked
        destinations = metadata.get("destinations", [])
        if destinations:
            dest_info = destinations[0]
            is_staked_dest = (dest_info.get("type", "staked") == "staked")
        else:
            is_staked_dest = True  # Default to staked
        
        # Derive destination address and signing key using destination mnemonic
        destination_address, destination_signing_key, _ = derive_address_from_mnemonic(
            dest_mnemonic, dest_account, dest_index, network, use_cip1852, staked=is_staked_dest
        )
        
        print(f"Using destination from command-line arguments:")
        print(f"  Account: {dest_account}, Index: {dest_index}")
        print(f"  Address: {destination_address}\n")
    else:
        # Get destination from metadata.destinations (use first one)
        destinations = metadata.get("destinations", [])
        if not destinations:
            raise ValueError("No destinations found in allocation report")
        
        dest_info = destinations[0]  # Use first destination
        dest_account = dest_info.get("account", 0)
        dest_index = dest_info.get("index", 0)
        
        # Derive destination address and signing key using destination mnemonic
        is_staked_dest = (dest_info.get("type", "staked") == "staked")
        destination_address, destination_signing_key, _ = derive_address_from_mnemonic(
            dest_mnemonic, dest_account, dest_index, network, use_cip1852, staked=is_staked_dest
        )
        
        # Verify destination address matches
        expected_dest = dest_info.get("address")
        if expected_dest and destination_address != expected_dest:
            print(f"Warning: Derived destination address doesn't match report!")
            print(f"  Expected: {expected_dest}")
            print(f"  Derived:  {destination_address}")
            print(f"  Using derived address...\n")
    
    return address_data, destination_address, destination_signing_key


def generate_consolidation_commands(
    json_path: str,
    mnemonic: str,
    output_file: str = "consolidation_commands.sh",
    destination_mnemonic: Optional[str] = None,
    destination_account: Optional[int] = None,
    destination_index: Optional[int] = None,
) -> None:
    """
    Generate bash script with curl commands for consolidating NIGHT tokens.
    
    Only supports allocation report format (from check_all_allocations.py).
    Only generates commands for addresses with NIGHT allocations > 0.
    
    IMPORTANT: This function ONLY generates commands - it NEVER executes them.
    You must review and execute the generated commands manually.
    
    Args:
        json_path: Path to allocation report JSON file (from check_all_allocations.py)
        mnemonic: BIP39 mnemonic phrase to derive source address signing keys
        output_file: Path to output bash script file (default: consolidation_commands.sh)
        destination_mnemonic: Optional BIP39 mnemonic phrase for destination (if different from source)
        destination_account: Optional account number to override destination from report
        destination_index: Optional index to override destination from report
    """
    print(f"Loading allocation report from: {json_path}")
    
    # Load allocation report and derive keys
    address_data, destination_address, destination_signing_key = load_allocation_report(
        json_path, mnemonic, destination_mnemonic, destination_account, destination_index
    )
    
    # Allocation report format
    metadata = address_data.get("metadata", {})
    network_str = metadata.get("network", "MAINNET")
    network = Network.MAINNET if network_str.lower() == "mainnet" else Network.TESTNET
    use_cip1852 = True  # Default to CIP-1852
    
    # Get registered addresses with NIGHT allocations
    registered_addresses = address_data.get("addresses", {}).get("registered", [])
    
    # Filter to only addresses with NIGHT allocations > 0
    source_addresses = [
        addr for addr in registered_addresses 
        if addr.get("night_allocation_night", 0.0) > 0
    ]
    
    # Calculate totals
    total_night = sum(addr.get('night_allocation_night', 0.0) for addr in source_addresses)
    total_star = sum(addr.get('night_allocation_star', 0) for addr in source_addresses)
    total_solutions = sum(addr.get('crypto_receipts', 0) for addr in source_addresses)
    
    print(f"Network: {network_str}")
    print(f"Destination address: {destination_address}")
    print(f"Total registered addresses: {len(registered_addresses)}")
    print(f"Addresses with NIGHT allocations: {len(source_addresses)}")
    print(f"Total to consolidate:")
    print(f"  - NIGHT: {total_night:,.6f} NIGHT")
    print(f"  - STAR: {total_star:,} STAR")
    print(f"  - Solutions: {total_solutions:,}")
    print(f"Generating consolidation commands...\n")
    print("⚠️  IMPORTANT: This script only generates commands - it NEVER executes them!")
    print("⚠️  Review the generated commands before executing them manually.\n")
    
    commands = []
    
    for addr_info in source_addresses:
        address = addr_info.get("address")
        account = addr_info.get("account")
        index = addr_info.get("index")
        addr_type = addr_info.get("type", "unknown")
        
        if not address:
            print(f"⚠️  Skipping entry with missing address: {addr_info}")
            continue
        
        # Skip if same as destination
        if address == destination_address:
            print(f"⚠️  Skipping address (same as destination): {address[:50]}...")
            continue
        
        # Derive signing key for this address
        try:
            if account is not None and index is not None:
                # Determine if this is a staked or enterprise address based on type
                is_staked = (addr_type == "staked")
                
                # Derive from account/index
                _, signing_key, _ = derive_address_from_mnemonic(
                    mnemonic, account, index, network, use_cip1852, staked=is_staked
                )
                display_name = f"account {account}, index {index} ({addr_type})"
            else:
                print(f"⚠️  Skipping {address[:50]}... (no account/index info)")
                continue
        except Exception as e:
            print(f"⚠️  Could not derive key for {address[:50]}...: {e}")
            continue
        
        # Generate command
        try:
            curl_command = generate_consolidation_command(
                address,
                destination_address,
                signing_key,
                destination_signing_key,
            )
            # Get holdings information from allocation report
            night_allocation = addr_info.get("night_allocation_night", 0.0)
            solutions = addr_info.get("crypto_receipts", 0)
            
            commands.append({
                "command": curl_command,
                "source_address": address,
                "account": account,
                "index": index,
                "type": addr_type,
                "night_allocation": night_allocation,
                "solutions": solutions,
            })
            
            print(f"✅ Generated command for {display_name}")
            print(f"   Holdings: {night_allocation:,.6f} NIGHT, {solutions} solutions")
        except Exception as e:
            print(f"❌ Error generating command for {address[:50]}...: {e}")
            continue
    
    # Write commands to file
    try:
        with open(output_file, 'w') as f:
            f.write("#!/bin/bash\n")
            f.write("# NIGHT Token Consolidation Commands\n")
            f.write(f"# Generated from: {json_path}\n")
            f.write(f"# Destination: {destination_address}\n")
            f.write(f"# Total commands: {len(commands)}\n")
            f.write("#\n")
            f.write("# IMPORTANT: Review these commands before executing!\n")
            f.write("# This script only generates commands - it NEVER executes them automatically.\n")
            f.write("# Execute commands manually or run this script with: bash consolidation_commands.sh\n")
            f.write("#\n\n")
            
            for i, cmd_info in enumerate(commands, 1):
                f.write(f"# {i}. Account {cmd_info['account']}, Index {cmd_info['index']} ({cmd_info['type']})\n")
                f.write(f"# Source: {cmd_info['source_address']}\n")
                f.write(f"# Holdings:\n")
                f.write(f"#   - NIGHT: {cmd_info['night_allocation']:,.6f} NIGHT\n")
                f.write(f"#   - Solutions: {cmd_info['solutions']:,}\n")
                f.write(f"{cmd_info['command']}\n")
                f.write(f"echo \"Command {i}/{len(commands)} completed\"\n")
                f.write(f"sleep 1  # Small delay between requests\n")
                f.write("\n")
        
        # Make the script executable
        import os
        os.chmod(output_file, 0o755)
        
        print(f"\n{'='*60}")
        print(f"✅ Generated {len(commands)} consolidation commands")
        print(f"✅ Saved to: {output_file}")
        print(f"\n⚠️  IMPORTANT: Review the commands before executing!")
        print(f"\nTo execute all commands:")
        print(f"  bash {output_file}")
        print(f"\nOr execute commands one by one manually.")
        print(f"{'='*60}")
    except Exception as e:
        print(f"\n❌ Error writing to file: {e}")
        import traceback
        traceback.print_exc()


def consolidate_addresses(
    json_path: str,
    mnemonic: str,
    report_file: str = "consolidation_report.json",
    delay: float = 1.0,
    destination_mnemonic: Optional[str] = None,
    destination_account: Optional[int] = None,
    destination_index: Optional[int] = None,
) -> None:
    """
    Consolidate NIGHT tokens from multiple addresses to the destination.
    
    Only supports allocation report format (from check_all_allocations.py).
    Only consolidates addresses with NIGHT allocations > 0.
    Generates a detailed report at the end.
    
    Args:
        json_path: Path to allocation report JSON file (from check_all_allocations.py)
        mnemonic: BIP39 mnemonic phrase to derive source address signing keys
        report_file: Path to output report file (default: consolidation_report.json)
        delay: Delay between requests in seconds (default: 1.0)
        destination_mnemonic: Optional BIP39 mnemonic phrase for destination (if different from source)
        destination_account: Optional account number to override destination from report
        destination_index: Optional index to override destination from report
    """
    print(f"Loading allocation report from: {json_path}")
    
    # Load allocation report and derive keys
    address_data, destination_address, destination_signing_key = load_allocation_report(
        json_path, mnemonic, destination_mnemonic, destination_account, destination_index
    )
    
    # Allocation report format
    metadata = address_data.get("metadata", {})
    network_str = metadata.get("network", "MAINNET")
    network = Network.MAINNET if network_str.lower() == "mainnet" else Network.TESTNET
    use_cip1852 = True  # Default to CIP-1852
    
    # Get registered addresses with NIGHT allocations
    registered_addresses = address_data.get("addresses", {}).get("registered", [])
    
    # Filter to only addresses with NIGHT allocations > 0
    source_addresses = [
        addr for addr in registered_addresses 
        if addr.get("night_allocation_night", 0.0) > 0
    ]
    
    # Calculate totals
    total_night = sum(addr.get('night_allocation_night', 0.0) for addr in source_addresses)
    total_star = sum(addr.get('night_allocation_star', 0) for addr in source_addresses)
    total_solutions = sum(addr.get('crypto_receipts', 0) for addr in source_addresses)
    
    print(f"Network: {network_str}")
    print(f"Destination address: {destination_address}")
    print(f"Total registered addresses: {len(registered_addresses)}")
    print(f"Addresses with NIGHT allocations: {len(source_addresses)}")
    print(f"Total to consolidate:")
    print(f"  - NIGHT: {total_night:,.6f} NIGHT")
    print(f"  - STAR: {total_star:,} STAR")
    print(f"  - Solutions: {total_solutions:,}")
    print(f"\nStarting consolidation...\n")
    
    # Track consolidation results
    consolidations = {
        "successful": [],
        "already_consolidated": [],
        "failed": [],
        "errors": [],
    }
    
    # Track totals per destination
    destination_totals = defaultdict(lambda: {"night": 0.0, "solutions": 0, "count": 0})
    
    for addr_info in source_addresses:
        address = addr_info.get("address")
        account = addr_info.get("account")
        index = addr_info.get("index")
        addr_type = addr_info.get("type", "unknown")
        
        if not address:
            print(f"⚠️  Skipping entry with missing address: {addr_info}")
            continue
        
        # Skip if same as destination
        if address == destination_address:
            print(f"⚠️  Skipping address (same as destination): {address[:50]}...")
            continue
        
        # Derive signing key for this address
        try:
            if account is not None and index is not None:
                # Determine if this is a staked or enterprise address based on type
                is_staked = (addr_type == "staked")
                
                # Derive from account/index
                _, signing_key, _ = derive_address_from_mnemonic(
                    mnemonic, account, index, network, use_cip1852, staked=is_staked
                )
                display_name = f"account {account}, index {index} ({addr_type})"
            else:
                print(f"⚠️  Skipping {address[:50]}... (no account/index info)")
                continue
        except Exception as e:
            print(f"⚠️  Could not derive key for {address[:50]}...: {e}")
            continue
        
        # Get holdings information from allocation report
        night_allocation = addr_info.get("night_allocation_night", 0.0)
        star_allocation = addr_info.get("night_allocation_star", 0)
        solutions = addr_info.get("crypto_receipts", 0)
        
        print(f"[{len(consolidations['successful']) + len(consolidations['already_consolidated']) + len(consolidations['failed']) + len(consolidations['errors']) + 1}/{len(source_addresses)}] {display_name}")
        print(f"  Source: {address[:50]}...")
        print(f"  Holdings: {night_allocation:,.6f} NIGHT, {solutions} solutions")
        
        # Generate consolidation command (URL with signature)
        try:
            api_url = generate_consolidation_command(
                address,
                destination_address,
                signing_key,
                destination_signing_key,
            )
            # Extract URL from curl command
            import re
            url_match = re.search(r"curl -X POST '([^']+)'", api_url)
            if url_match:
                api_url = url_match.group(1)
            else:
                print(f"  ❌ Error: Could not extract URL from command")
                consolidations["errors"].append({
                    "source": address,
                    "destination": destination_address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "night": night_allocation,
                    "solutions": solutions,
                    "error": "Could not extract URL from command",
                })
                continue
        except Exception as e:
            print(f"  ❌ Error generating command: {e}")
            consolidations["errors"].append({
                "source": address,
                "destination": destination_address,
                "account": account,
                "index": index,
                "type": addr_type,
                "night": night_allocation,
                "solutions": solutions,
                "error": str(e),
            })
            continue
        
        # Make the API request
        try:
            response = requests.post(api_url, timeout=30)
            
            # Parse response
            try:
                data = response.json()
                status_code = response.status_code
                message = data.get("message", "")
                error = data.get("error", "")
            except:
                data = {}
                status_code = response.status_code
                message = response.text[:200]
                error = f"HTTP {status_code}"
            
            if status_code == 200:
                # Successfully consolidated
                print(f"  ✅ Successfully consolidated!")
                consolidations["successful"].append({
                    "source": address,
                    "destination": destination_address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "night": night_allocation,
                    "solutions": solutions,
                })
                destination_totals[destination_address]["night"] += night_allocation
                destination_totals[destination_address]["solutions"] += solutions
                destination_totals[destination_address]["count"] += 1
                
            elif status_code == 409:
                # Extract actual destination from message
                # Format: "already has an active donation assignment to <address>"
                import re
                match = re.search(r'to (addr1[\w]+)', message)
                if match:
                    actual_dest = match.group(1)
                    if actual_dest == destination_address:
                        # Already consolidated to correct destination
                        print(f"  ℹ️  Already consolidated to destination")
                        consolidations["already_consolidated"].append({
                            "source": address,
                            "destination": destination_address,
                            "account": account,
                            "index": index,
                            "type": addr_type,
                            "night": night_allocation,
                            "solutions": solutions,
                        })
                        destination_totals[destination_address]["night"] += night_allocation
                        destination_totals[destination_address]["solutions"] += solutions
                        destination_totals[destination_address]["count"] += 1
                    else:
                        # Already consolidated to different destination
                        print(f"  ⚠️  Already consolidated to DIFFERENT destination: {actual_dest}")
                        consolidations["failed"].append({
                            "source": address,
                            "intended_destination": destination_address,
                            "actual_destination": actual_dest,
                            "account": account,
                            "index": index,
                            "type": addr_type,
                            "night": night_allocation,
                            "solutions": solutions,
                            "error": f"Already consolidated to different destination: {actual_dest}",
                        })
                else:
                    # Could not extract destination from message
                    print(f"  ⚠️  Conflict (409): {message}")
                    consolidations["failed"].append({
                        "source": address,
                        "destination": destination_address,
                        "account": account,
                        "index": index,
                        "type": addr_type,
                        "night": night_allocation,
                        "solutions": solutions,
                        "error": message,
                    })
                    
            elif status_code == 404:
                print(f"  ⚠️  Address not registered or has no rewards (404)")
                consolidations["failed"].append({
                    "source": address,
                    "destination": destination_address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "night": night_allocation,
                    "solutions": solutions,
                    "error": "Address not registered or has no rewards",
                })
            else:
                print(f"  ❌ Error ({status_code}): {message or error}")
                consolidations["failed"].append({
                    "source": address,
                    "destination": destination_address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "night": night_allocation,
                    "solutions": solutions,
                    "error": message or error,
                    "status_code": status_code,
                })
                
        except Exception as e:
            print(f"  ❌ Exception: {e}")
            consolidations["errors"].append({
                "source": address,
                "destination": destination_address,
                "account": account,
                "index": index,
                "type": addr_type,
                "night": night_allocation,
                "solutions": solutions,
                "error": str(e),
            })
        
        print()
        
        # Delay between requests
        if len(consolidations['successful']) + len(consolidations['already_consolidated']) + len(consolidations['failed']) + len(consolidations['errors']) < len(source_addresses):
            time.sleep(delay)
    
    # Generate report
    print("=" * 80)
    print("CONSOLIDATION REPORT")
    print("=" * 80)
    print()
    
    # Summary
    total_successful = len(consolidations["successful"])
    total_already = len(consolidations["already_consolidated"])
    total_failed = len(consolidations["failed"])
    total_errors = len(consolidations["errors"])
    
    print("SUMMARY")
    print("-" * 80)
    print(f"Total addresses processed: {len(source_addresses)}")
    print(f"✅ Successfully consolidated: {total_successful}")
    print(f"ℹ️  Already consolidated: {total_already}")
    print(f"❌ Failed: {total_failed}")
    print(f"⚠️  Errors: {total_errors}")
    print()
    
    # Totals by destination
    print("TOTALS BY DESTINATION")
    print("-" * 80)
    for dest, totals in sorted(destination_totals.items()):
        print(f"Destination: {dest}")
        print(f"  Addresses: {totals['count']}")
        print(f"  Total NIGHT: {totals['night']:,.6f} NIGHT")
        print(f"  Total Solutions: {totals['solutions']:,}")
        print()
    
    # Save detailed report to JSON
    report = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "source_file": json_path,
            "destination_address": destination_address,
            "total_addresses": len(source_addresses),
        },
        "summary": {
            "successful": total_successful,
            "already_consolidated": total_already,
            "failed": total_failed,
            "errors": total_errors,
        },
        "destination_totals": {k: dict(v) for k, v in destination_totals.items()},
        "consolidations": consolidations,
    }
    
    try:
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"✅ Detailed report saved to: {report_file}")
        print("=" * 80)
    except Exception as e:
        print(f"\n❌ Error writing report file: {e}")
        import traceback
        traceback.print_exc()




def main():
    parser = argparse.ArgumentParser(
        description="Consolidate NIGHT tokens from multiple addresses into one destination",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
This script consolidates NIGHT tokens from addresses in an allocation report to a destination address.
It executes the consolidations and generates a detailed report at the end.

Examples:
  # Consolidate from allocation report (only addresses with NIGHT)
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 word2 ... word24"
  
  # Override destination using account/index (same mnemonic)
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 ... word24" --destination-account 1 --destination-index 1
  
  # Override destination using different mnemonic
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 ... word24" --destination-mnemonic "dest word1 ... word24" --destination-account 1 --destination-index 1
  
  # Specify custom report file and delay
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 ... word24" --report my_report.json --delay 2.0
  
  # Generate bash script with commands instead of executing
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 ... word24" --generate-commands
  
  # Generate commands with custom output file and destination
  python consolidate_night.py --addresses fri_allocations_report.json --mnemonic "word1 ... word24" --generate-commands --output my_commands.sh --destination-account 1 --destination-index 1
  
  # Check the generated report
  cat consolidation_report.json
        """
    )
    
    parser.add_argument(
        "--addresses",
        type=str,
        required=True,
        help="Path to allocation report JSON file (from check_all_allocations.py)",
    )
    
    parser.add_argument(
        "--mnemonic",
        type=str,
        required=True,
        help="BIP39 mnemonic phrase (12 or 24 words) - used to derive signing keys",
    )
    
    parser.add_argument(
        "--report",
        type=str,
        default="consolidation_report.json",
        help="Output file for consolidation report (default: consolidation_report.json)",
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay between requests in seconds (default: 1.0)",
    )
    
    parser.add_argument(
        "--generate-commands",
        action="store_true",
        help="Generate bash script with commands instead of executing consolidations",
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="consolidation_commands.sh",
        help="Output file for generated bash script (default: consolidation_commands.sh, only used with --generate-commands)",
    )
    
    parser.add_argument(
        "--destination-mnemonic",
        type=str,
        help="BIP39 mnemonic phrase for destination address (if different from source mnemonic)",
    )
    
    parser.add_argument(
        "--destination-account",
        type=int,
        help="Account number for destination address (overrides allocation report destination)",
    )
    
    parser.add_argument(
        "--destination-index",
        type=int,
        help="Index for destination address (overrides allocation report destination)",
    )
    
    args = parser.parse_args()
    
    # Validate mnemonic
    mnemonic_words = args.mnemonic.strip().split()
    if len(mnemonic_words) not in [12, 15, 18, 21, 24]:
        print("Error: Mnemonic must be 12, 15, 18, 21, or 24 words")
        return
    
    mnemonic = " ".join(mnemonic_words)
    
    # Validate destination mnemonic if provided
    destination_mnemonic = None
    if args.destination_mnemonic:
        dest_mnemonic_words = args.destination_mnemonic.strip().split()
        if len(dest_mnemonic_words) not in [12, 15, 18, 21, 24]:
            print("Error: Destination mnemonic must be 12, 15, 18, 21, or 24 words")
            return
        destination_mnemonic = " ".join(dest_mnemonic_words)
    
    # Validate destination account/index (both must be provided together)
    if (args.destination_account is not None) != (args.destination_index is not None):
        print("Error: --destination-account and --destination-index must be provided together")
        return
    
    # Execute consolidations or generate commands
    try:
        if args.generate_commands:
            generate_consolidation_commands(
                json_path=args.addresses,
                mnemonic=mnemonic,
                output_file=args.output,
                destination_mnemonic=destination_mnemonic,
                destination_account=args.destination_account,
                destination_index=args.destination_index,
            )
        else:
            consolidate_addresses(
                json_path=args.addresses,
                mnemonic=mnemonic,
                report_file=args.report,
                delay=args.delay,
                destination_mnemonic=destination_mnemonic,
                destination_account=args.destination_account,
                destination_index=args.destination_index,
            )
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except FileNotFoundError:
        print(f"\n\nError: Allocation report file not found: {args.addresses}")
        print("Generate it first using: python check_all_allocations.py --help")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()
