#!/usr/bin/env python3
"""
Register Addresses Script

This script registers addresses from a JSON file with the Scavenger Mine API.
Registration is required before addresses can participate in mining.
"""

import argparse
import json
import time
import urllib.parse
import requests
from typing import Optional
from consolidate_night import (
    API_BASE_URL,
    derive_address_from_mnemonic,
    load_addresses_from_json,
    sign_message_cip30,
    get_terms_and_conditions,
)
from pycardano import Network, PaymentSigningKey


def register_address(
    address: str,
    signing_key: PaymentSigningKey,
    terms_message: Optional[str] = None,
    terms_version: Optional[str] = None,
    public_key_bytes: Optional[bytes] = None,
) -> dict:
    """
    Register an address with the Scavenger Mine API.
    
    Per API documentation: POST /register/{address}/{signature}/{pubkey}
    - address: Standard Cardano payment address
    - signature: Standard CIP 8/30 signature (signing the T&C message)
    - pubkey: 64 character hex encoded public key associated with the address
    
    Args:
        address: Cardano address to register
        signing_key: Signing key for the address
        terms_message: Optional Terms and Conditions message to sign
        terms_version: Optional Terms and Conditions version
    
    Returns:
        API response as dictionary
    """
    # Get Terms and Conditions if not provided
    if not terms_message:
        tc_data = get_terms_and_conditions()
        if "error" in tc_data:
            return {
                "error": f"Failed to get Terms and Conditions: {tc_data.get('error')}",
                "statusCode": tc_data.get("statusCode", 500),
            }
        terms_message = tc_data.get("message", "")
        terms_version = tc_data.get("version", "")
    
    # Sign the Terms and Conditions message (exactly as returned from GET /TandC)
    # For registration endpoint, use CBOR format (use_cbor=True)
    signature = sign_message_cip30(terms_message, signing_key, address, use_cbor=True)
    
    # Get the public key - use the provided one if available (matches the address)
    # Per API docs: pubkey is "64 character hex encoded - associated with the address"
    # This is the Ed25519 public key (32 bytes = 64 hex characters)
    if public_key_bytes is not None:
        # Use the public key that was used to create the address
        pubkey_hex = public_key_bytes.hex()
    else:
        # Fallback: try to derive from signing key (may not match address)
        from pycardano import PaymentVerificationKey
        verification_key = signing_key.to_verification_key()
        try:
            pubkey_bytes = bytes(verification_key)
            if len(pubkey_bytes) != 32:
                import nacl.signing
                signing_key_bytes = bytes(signing_key)
                if len(signing_key_bytes) >= 32:
                    private_key = signing_key_bytes[:32]
                else:
                    private_key = signing_key_bytes
                nacl_signing_key = nacl.signing.SigningKey(private_key)
                verify_key = nacl_signing_key.verify_key
                pubkey_bytes = bytes(verify_key)
            pubkey_hex = pubkey_bytes.hex()
        except Exception as e:
            return {
                "error": f"Failed to extract public key: {str(e)}",
                "statusCode": 500,
            }
    
    # Ensure pubkey is exactly 64 hex characters (32 bytes)
    if len(pubkey_hex) != 64:
        return {
            "error": f"Invalid public key length: {len(pubkey_hex)} (expected 64 hex characters)",
            "statusCode": 500,
        }
    
    # URL encode the address, signature, and pubkey
    address_encoded = urllib.parse.quote(address, safe='')
    signature_encoded = urllib.parse.quote(signature, safe='')
    pubkey_encoded = urllib.parse.quote(pubkey_hex, safe='')
    
    # Construct the API endpoint per documentation: POST /register/{address}/{signature}/{pubkey}
    url = f"{API_BASE_URL}/register/{address_encoded}/{signature_encoded}/{pubkey_encoded}"
    
    headers = {
        'User-Agent': 'NIGHT-Registration-Script/1.0',
    }
    
    # Make the API call
    try:
        response = requests.post(url, timeout=30, headers=headers)
        
        # For debugging: log full response for 500 errors
        if response.status_code == 500:
            # Try to get full response details
            try:
                response_text = response.text
                response_headers = dict(response.headers) if hasattr(response, 'headers') else {}
            except:
                response_text = "Could not read response"
                response_headers = {}
        else:
            response_text = None
            response_headers = None
        
        # Try to parse JSON response
        try:
            response_data = response.json()
            # Always include statusCode for easier checking
            response_data["statusCode"] = response.status_code
            if response.status_code >= 400:
                # Include full error details
                if "error" not in response_data and "message" not in response_data:
                    response_data["error"] = response.text[:500] if response.text else "Unknown error"
                # For 500 errors, include full response
                if response.status_code == 500 and response_text:
                    response_data["full_response"] = response_text[:1000]
            return response_data
        except json.JSONDecodeError:
            # If not JSON, return text response with more details
            error_text = response.text[:1000] if response.text else "No error message"
            result = {
                "statusCode": response.status_code,
                "text": error_text,
                "error": f"HTTP {response.status_code}: {error_text[:200]}",
            }
            if response_headers:
                result["headers"] = response_headers
            return result
    except requests.exceptions.HTTPError as e:
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


def register_addresses_from_json(
    json_path: str,
    mnemonic: str,
    delay_between_requests: float = 1.0,
    max_addresses: Optional[int] = None,
) -> None:
    """
    Register addresses from a JSON file with the Scavenger Mine API.
    
    Args:
        json_path: Path to JSON file containing address list
        mnemonic: BIP39 mnemonic phrase to derive signing keys
        delay_between_requests: Delay in seconds between API requests (default: 1.0)
        max_addresses: Maximum number of addresses to register (None = all)
    """
    print(f"Loading addresses from: {json_path}")
    
    # Load addresses and derive keys
    address_data, destination_address, destination_signing_key = load_addresses_from_json(
        json_path, mnemonic
    )
    
    network_str = address_data.get("network", "testnet")
    source_addresses = address_data.get("source_addresses", [])
    use_cip1852 = address_data.get("use_cip1852", True)
    
    print(f"Network: {network_str.upper()}")
    print(f"Total addresses to register: {len(source_addresses)}")
    if max_addresses:
        print(f"Limiting to first {max_addresses} addresses")
    print()
    
    # Determine network for derivation
    network = Network.MAINNET if network_str == "mainnet" else Network.TESTNET
    
    # Get Terms and Conditions once (shared for all addresses)
    print("Fetching Terms and Conditions...")
    tc_data = get_terms_and_conditions()
    if "error" in tc_data:
        print(f"⚠️  Warning: Could not fetch Terms and Conditions: {tc_data.get('error')}")
        print("  Will attempt registration without T&C message")
        terms_message = None
        terms_version = None
    else:
        terms_message = tc_data.get("message", "")
        terms_version = tc_data.get("version", "")
        print(f"✅ Terms and Conditions version: {terms_version}")
        print()
    
    # Limit addresses if specified
    addresses_to_register = source_addresses[:max_addresses] if max_addresses else source_addresses
    
    # Register each address
    successful = 0
    failed = 0
    skipped = 0
    already_registered = 0
    
    results = []
    
    for i, addr_info in enumerate(addresses_to_register, 1):
        address = addr_info.get("address")
        account = addr_info.get("account")
        index = addr_info.get("index")
        addr_type = addr_info.get("type", "unknown")
        
        if not address:
            print(f"[{i}/{len(addresses_to_register)}] ⚠️  Skipping entry with missing address")
            skipped += 1
            continue
        
        # Derive signing key and public key for this address
        # Use pycardano HDWallet derivation (matches Eternl wallet, correct addresses)
        try:
            if account is not None and index is not None:
                # Determine if this is a staked or enterprise address based on type
                is_staked = (addr_type == "staked")
                
                # Use pycardano HDWallet derivation (matches Eternl wallet, correct addresses)
                # Pass staked parameter to match the address type from JSON
                derived_address, signing_key, public_key_bytes = derive_address_from_mnemonic(
                    mnemonic, account, index, network, use_cip1852, staked=is_staked
                )
                
                # Verify the derived address matches the JSON address
                if derived_address != address:
                    print(f"    ⚠️  Warning: Derived address doesn't match JSON address!")
                    print(f"       JSON: {address}")
                    print(f"       Derived: {derived_address}")
                    print(f"       This might cause registration issues")
                
                # Keep the address from JSON (it's correct and matches Eternl)
                # The public_key_bytes from derive_address_from_mnemonic matches the wallet's public key
                display_name = f"account {account}, index {index} ({addr_type})"
            else:
                print(f"[{i}/{len(addresses_to_register)}] ⚠️  Skipping {address[:50]}... (no account/index info)")
                skipped += 1
                continue
        except Exception as e:
            print(f"[{i}/{len(addresses_to_register)}] ⚠️  Could not derive key for {address[:50]}...: {e}")
            skipped += 1
            continue
        
        print(f"[{i}/{len(addresses_to_register)}] Registering: {display_name}")
        print(f"    Address: {address[:50]}...")
        

        try:
            # Use the public key that matches the address
            result = register_address(
                address,
                signing_key,
                terms_message,
                terms_version,
                public_key_bytes,
            )
            
            result_entry = {
                "address": address,
                "account": account,
                "index": index,
                "type": addr_type,
                "status_code": result.get("statusCode"),
            }
            
            status_code = result.get("statusCode", 200)
            
            # Check for already registered based on API behavior:
            # - 409 Conflict: explicitly indicates already registered (per API docs)
            # - 400 Bad Request with "already registered" in message
            # - 201 Created: already registered (returns existing registration)
            # - 200 OK: new registration (successfully created)
            if status_code == 409:
                # 409 Conflict means already registered (per API documentation)
                print(f"    ℹ️  Already registered (409 Conflict)")
                already_registered += 1
                result_entry["status"] = "already_registered"
            elif status_code == 400:
                error_message = result.get("message", result.get("error", "Unknown error"))
                
                # Check if this address is already registered (not just the public key)
                # "already registered" without "another wallet address" means THIS address is registered
                # "already registered with another wallet address" means the public key is registered to a DIFFERENT address
                if "already registered" in error_message.lower():
                    if "another wallet address" in error_message.lower() or "different" in error_message.lower():
                        # Public key registered to different address = this address is NOT registered
                        print(f"    ❌ Error: Public key already registered to a different address")
                        print(f"       This means this address is NOT registered")
                        print(f"       Error: {error_message}")
                        failed += 1
                        result_entry["status"] = "failed"
                        result_entry["error"] = error_message
                    else:
                        # This address is already registered
                        print(f"    ℹ️  Already registered (400 Bad Request)")
                        already_registered += 1
                        result_entry["status"] = "already_registered"
                elif "already exists" in error_message.lower():
                    print(f"    ℹ️  Already registered (400 Bad Request)")
                    already_registered += 1
                    result_entry["status"] = "already_registered"
                else:
                    # Other 400 errors - show the actual error message
                    print(f"    ❌ Error (Status {status_code}): {error_message}")
                    failed += 1
                    result_entry["status"] = "failed"
                    result_entry["error"] = error_message
            elif status_code == 201:
                # 201 Created = already registered (returns existing registration)
                print(f"    ℹ️  Already registered (201 Created)")
                already_registered += 1
                result_entry["status"] = "already_registered"
            elif status_code == 200:
                # 200 OK = new registration (successfully created)
                print(f"    ✅ Successfully registered!")
                successful += 1
                result_entry["status"] = "success"
            elif "error" in result or status_code >= 400:
                error_message = result.get("message", result.get("error", "Unknown error"))
                if status_code == 404:
                    # 404 could mean address not found or endpoint issue
                    if "not registered" in error_message.lower() or "not found" in error_message.lower():
                        print(f"    ⚠️  Address not found or not registered (404)")
                    else:
                        print(f"    ⚠️  Registration endpoint error (404)")
                    failed += 1
                    result_entry["status"] = "failed"
                    result_entry["error"] = error_message
                else:
                    print(f"    ❌ Error (Status {status_code}): {error_message}")
                    # For 500 errors, show more details if available
                    if status_code == 500:
                        print(f"    ⚠️  Server returned 500 - this may indicate:")
                        print(f"       - Request format issue")
                        print(f"       - Server-side processing error")
                        print(f"       - Signature/CBOR format problem")
                        if "text" in result:
                            details = result.get('text', '')
                            if details and len(details) > 20:
                                print(f"    Response body: {details[:300]}")
                        if "full_response" in result:
                            print(f"    Full response: {result.get('full_response', '')[:300]}")
                        if "error" in result and result["error"] != error_message:
                            print(f"    Error details: {result.get('error', '')[:300]}")
                    failed += 1
                    result_entry["status"] = "failed"
                    result_entry["error"] = error_message
                    # Include full error details in result
                    if "text" in result:
                        result_entry["error_details"] = result.get("text", "")
                    if "full_response" in result:
                        result_entry["full_response"] = result.get("full_response", "")
                    if "error" in result and result["error"] != error_message:
                        result_entry["full_error"] = result.get("error", "")
            
            results.append(result_entry)
            
        except Exception as e:
            print(f"    ❌ Exception: {e}")
            failed += 1
            results.append({
                "address": address,
                "account": account,
                "index": index,
                "type": addr_type,
                "status": "failed",
                "error": str(e),
            })
        
        # Delay between requests to avoid rate limiting
        if i < len(addresses_to_register):
            time.sleep(delay_between_requests)
        
        print()
    
    # Print summary
    print(f"\n{'='*60}")
    print(f"Registration complete!")
    print(f"  ✅ Successful: {successful}")
    print(f"  ℹ️  Already registered: {already_registered}")
    print(f"  ⚠️  Skipped: {skipped}")
    print(f"  ❌ Failed: {failed}")
    print(f"  📊 Total processed: {len(addresses_to_register)}")
    print(f"{'='*60}")
    
    # Save results to JSON file
    output_file = "registration_results.json"
    try:
        with open(output_file, 'w') as f:
            json.dump({
                "summary": {
                    "total": len(addresses_to_register),
                    "successful": successful,
                    "already_registered": already_registered,
                    "skipped": skipped,
                    "failed": failed,
                },
                "results": results,
            }, f, indent=2)
        print(f"\n✅ Results saved to: {output_file}")
    except Exception as e:
        print(f"\n⚠️  Could not save results: {e}")


def main():
    parser = argparse.ArgumentParser(
        description="Register addresses from JSON file with Scavenger Mine API",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register all addresses from JSON file
  python register_addresses.py --addresses addresses_enterprise.json --mnemonic "word1 word2 ... word24"
  
  # Register with custom delay between requests
  python register_addresses.py --addresses addresses_enterprise.json --mnemonic "word1 ... word24" --delay 2.0
  
  # Register only first 100 addresses
  python register_addresses.py --addresses addresses_enterprise.json --mnemonic "word1 ... word24" --max 100
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
    
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between API requests (default: 1.0)",
    )
    
    parser.add_argument(
        "--max",
        type=int,
        default=None,
        help="Maximum number of addresses to register (default: all)",
    )
    
    args = parser.parse_args()
    
    # Validate mnemonic
    mnemonic_words = args.mnemonic.strip().split()
    if len(mnemonic_words) not in [12, 15, 18, 21, 24]:
        print("Error: Mnemonic must be 12, 15, 18, 21, or 24 words")
        return
    
    mnemonic = " ".join(mnemonic_words)
    
    # Run registration
    try:
        register_addresses_from_json(
            json_path=args.addresses,
            mnemonic=mnemonic,
            delay_between_requests=args.delay,
            max_addresses=args.max,
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

