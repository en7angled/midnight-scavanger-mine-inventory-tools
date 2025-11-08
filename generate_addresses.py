#!/usr/bin/env python3
"""
Generate Address List Script

This script generates a JSON file containing Cardano addresses derived from a mnemonic phrase.
The generated JSON can be used with consolidate_night.py to consolidate NIGHT tokens.
"""

import argparse
import json
import copy
from typing import Optional, Tuple
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
# Note: We use pycardano's HDWallet for address generation (matches Eternl wallet)
# The signing key extraction is handled separately in consolidate_night.py


def derive_address_from_mnemonic(mnemonic: str, account: int, index: int = 0, network: Network = Network.TESTNET, use_cip1852: bool = True, staked: bool = True) -> Tuple[str, PaymentSigningKey]:
    """
    Derive a Cardano address from a mnemonic phrase.
    
    Uses pycardano's HDWallet which matches Eternl wallet derivation.
    This is the correct method for generating addresses that match wallet software.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        account: Account number
        index: Address index within the account (default: 0)
        network: Cardano network (TESTNET or MAINNET)
        use_cip1852: If True, use CIP-1852 (default), if False, use BIP44
        staked: If True, generate base address (addr1q) with stake, if False, generate enterprise address (addr1v) without stake
    
    Returns:
        Tuple of (address_string, signing_key)
    """
    # Use pycardano's HDWallet (matches Eternl wallet)
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
    
    # Extract private key for signing (xprivate_key is 64 bytes: chain code + private key)
    # Take the last 32 bytes which is the actual private key
    payment_private_key = payment_wallet.xprivate_key[32:] if len(payment_wallet.xprivate_key) >= 64 else payment_wallet.xprivate_key[:32]
    
    # Create signing key (needed for signing transactions)
    payment_signing_key = PaymentSigningKey.from_primitive(payment_private_key)
    
    # Create address hashes directly from public keys (Cardano uses blake2b-224)
    from hashlib import blake2b
    payment_hash = VerificationKeyHash(blake2b(payment_wallet.public_key, digest_size=28).digest())
    
    if staked:
        # Derive stake wallet for base address (addr1q)
        stake_wallet = wallet.derive_from_path(stake_path, private=True)
        stake_hash = VerificationKeyHash(blake2b(stake_wallet.public_key, digest_size=28).digest())
        
        # Create base address with both payment and stake parts
        address = Address(
            payment_part=payment_hash,
            staking_part=stake_hash,
            network=network,
        )
    else:
        # Create enterprise address (addr1v) without stake part
        address = Address(
            payment_part=payment_hash,
            network=network,
        )
    
    return str(address), payment_signing_key


def generate_address_list(
    mnemonic: str,
    accounts: list[int],
    max_index: int = 10,
    network: Network = Network.TESTNET,
    destination_account: int = 0,
    destination_index: int = 0,
    use_cip1852: bool = True,
    include_enterprise: bool = False,
) -> Tuple[dict, Optional[dict]]:
    """
    Generate JSON-compatible dictionaries of addresses.
    
    Args:
        mnemonic: BIP39 mnemonic phrase
        accounts: List of account numbers to generate addresses for
        max_index: Maximum address index per account
        network: Cardano network
        destination_account: Account number for destination address
        destination_index: Index for destination address
        use_cip1852: Use CIP-1852 derivation (default) or BIP44
        include_enterprise: If True, generate both staked (addr1q) and non-staked (addr1v) addresses
    
    Returns:
        Tuple of (staked_dict, non_staked_dict). If include_enterprise is False, non_staked_dict is None.
    """
    network_str = "mainnet" if network == Network.MAINNET else "testnet"
    
    # Derive destination address (always staked/base address)
    dest_address, _ = derive_address_from_mnemonic(
        mnemonic, destination_account, destination_index, network, use_cip1852, staked=True
    )
    
    # Base structure for both address types
    base_structure = {
        "network": network_str,
        "use_cip1852": use_cip1852,
        "destination": {
            "account": destination_account,
            "index": destination_index,
            "address": dest_address,
            "type": "staked",
        },
        "source_addresses": [],
    }
    
    # Use deep copy to ensure nested structures are independent
    staked_result = copy.deepcopy(base_structure)
    non_staked_result = copy.deepcopy(base_structure) if include_enterprise else None
    
    # Derive source addresses
    for account in accounts:
        for index in range(max_index + 1):
            try:
                # Generate staked address (base address, addr1q)
                staked_address, _ = derive_address_from_mnemonic(
                    mnemonic, account, index, network, use_cip1852, staked=True
                )
                
                # Skip if same as destination
                if staked_address != dest_address:
                    staked_result["source_addresses"].append({
                        "address": staked_address,
                        "account": account,
                        "index": index,
                        "type": "staked",
                    })
                
                # If requested, also generate enterprise address (non-staked, addr1v)
                if include_enterprise:
                    enterprise_address, _ = derive_address_from_mnemonic(
                        mnemonic, account, index, network, use_cip1852, staked=False
                    )
                    
                    # Skip if same as destination
                    if enterprise_address != dest_address:
                        non_staked_result["source_addresses"].append({
                            "address": enterprise_address,
                            "account": account,
                            "index": index,
                            "type": "non-staked",
                        })
                        
            except Exception as e:
                print(f"Warning: Could not derive address for account {account}, index {index}: {e}")
                continue
    
    return staked_result, non_staked_result


def main():
    parser = argparse.ArgumentParser(
        description="Generate a JSON file with Cardano addresses from a mnemonic",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Generate addresses for accounts 0-4
  python generate_addresses.py --mnemonic "word1 word2 ... word24" --accounts 0 1 2 3 4 -o addresses.json
  
  # Generate with destination account 5
  python generate_addresses.py --mnemonic "word1 word2 ... word24" --accounts 0 1 2 --destination-account 5 -o addresses.json
  
  # Use mainnet and check more indices
  python generate_addresses.py --mnemonic "word1 word2 ... word24" --accounts 0 1 2 --mainnet --max-index 20 -o addresses.json
  
  # Generate both staked and non-staked addresses
  python generate_addresses.py --mnemonic "word1 word2 ... word24" --accounts 0 1 2 --include-enterprise -o addresses.json
        """
    )
    
    parser.add_argument(
        "--mnemonic",
        type=str,
        required=True,
        help="BIP39 mnemonic phrase (12 or 24 words)",
    )
    
    parser.add_argument(
        "--accounts",
        type=int,
        nargs="+",
        required=True,
        help="Account numbers to generate addresses for (e.g., 0 1 2 3)",
    )
    
    parser.add_argument(
        "--destination-account",
        type=int,
        default=0,
        help="Account number for destination address (default: 0)",
    )
    
    parser.add_argument(
        "--destination-index",
        type=int,
        default=0,
        help="Address index for destination address (default: 0)",
    )
    
    parser.add_argument(
        "--max-index",
        type=int,
        default=200,
        help="Maximum address index to generate per account (default: 30)",
    )
    
    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="Use Cardano mainnet (default: testnet)",
    )
    
    parser.add_argument(
        "--bip44",
        action="store_true",
        help="Use BIP44 derivation instead of CIP-1852 (default: CIP-1852 for Eternl, Daedalus, Yoroi)",
    )
    
    parser.add_argument(
        "--include-enterprise",
        action="store_true",
        help="Also generate non-staked enterprise addresses (addr1v) in addition to staked addresses (addr1q)",
    )
    
    parser.add_argument(
        "-o", "--output",
        type=str,
        default="addresses.json",
        help="Output JSON file path (default: addresses.json)",
    )
    
    args = parser.parse_args()
    
    # Validate mnemonic
    mnemonic_words = args.mnemonic.strip().split()
    if len(mnemonic_words) not in [12, 15, 18, 21, 24]:
        print("Error: Mnemonic must be 12, 15, 18, 21, or 24 words")
        return
    
    mnemonic = " ".join(mnemonic_words)
    
    # Determine network
    network = Network.MAINNET if args.mainnet else Network.TESTNET
    use_cip1852 = not args.bip44  # Default to CIP-1852 unless --bip44 is specified
    
    # Generate address list
    try:
        print(f"Generating addresses from mnemonic...")
        print(f"Network: {'MAINNET' if network == Network.MAINNET else 'TESTNET'}")
        print(f"Derivation: {'CIP-1852' if use_cip1852 else 'BIP44'} (m/{'1852' if use_cip1852 else '44'}'/1815'/account'/0/index)")
        print(f"Accounts: {args.accounts}")
        print(f"Destination: account {args.destination_account}, index {args.destination_index}")
        print(f"Max index per account: {args.max_index}")
        print(f"Include enterprise addresses: {args.include_enterprise}\n")
        
        staked_data, non_staked_data = generate_address_list(
            mnemonic=mnemonic,
            accounts=args.accounts,
            max_index=args.max_index,
            network=network,
            destination_account=args.destination_account,
            destination_index=args.destination_index,
            use_cip1852=use_cip1852,
            include_enterprise=args.include_enterprise,
        )
        
        # Determine output filenames
        if args.include_enterprise:
            # Split filename into base and extension
            if '.' in args.output:
                base_name, ext = args.output.rsplit('.', 1)
                staked_output = f"{base_name}_staked.{ext}"
                non_staked_output = f"{base_name}_enterprise.{ext}"
            else:
                staked_output = f"{args.output}_staked"
                non_staked_output = f"{args.output}_enterprise"
        else:
            staked_output = args.output
            non_staked_output = None
        
        # Write staked addresses to file
        with open(staked_output, 'w') as f:
            json.dump(staked_data, f, indent=2)
        
        print(f"✅ Generated {len(staked_data['source_addresses'])} staked addresses (addr1q)")
        print(f"✅ Destination address: {staked_data['destination']['address']} (staked)")
        print(f"✅ Saved staked addresses to: {staked_output}")
        
        # Write non-staked addresses to separate file if requested
        if args.include_enterprise and non_staked_data:
            with open(non_staked_output, 'w') as f:
                json.dump(non_staked_data, f, indent=2)
            
            print(f"✅ Generated {len(non_staked_data['source_addresses'])} non-staked addresses (addr1v)")
            print(f"✅ Saved non-staked addresses to: {non_staked_output}")
        
        print(f"\nYou can now use these files with consolidate_night.py:")
        print(f"  python consolidate_night.py --addresses {staked_output} --mnemonic \"{args.mnemonic}\"")
        if args.include_enterprise:
            print(f"  python consolidate_night.py --addresses {non_staked_output} --mnemonic \"{args.mnemonic}\"")
        
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

