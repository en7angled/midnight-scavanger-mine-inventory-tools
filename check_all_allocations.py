#!/usr/bin/env python3
"""
Check All Address Allocations Script

This script reads source addresses from a JSON file and checks each address's
NIGHT allocation from the Scavenger Mine API, then generates a summary report.
"""

import argparse
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Optional


# Browser API base URL
BROWSER_API_BASE_URL = "https://sm.midnight.gd/api"


def get_address_statistics(address: str, max_retries: int = 3, retry_delay: float = 2.0) -> dict:
    """
    Get statistics for an address from the browser API.
    
    Args:
        address: Cardano address to check
        max_retries: Maximum number of retries on rate limit (default: 3)
        retry_delay: Initial delay between retries in seconds (default: 2.0)
    
    Returns:
        Dictionary with statistics data
    """
    url = f"{BROWSER_API_BASE_URL}/statistics/{address}"
    
    # Use browser-like headers to avoid security checkpoints
    headers = {
        'Accept': '*/*',
        'Accept-Encoding': 'gzip, deflate, br',
        'Accept-Language': 'en-GB,en;q=0.9',
        'Content-Type': 'application/json',
        'Referer': 'https://sm.midnight.gd/wizard/mine',
        'Sec-Fetch-Dest': 'empty',
        'Sec-Fetch-Mode': 'cors',
        'Sec-Fetch-Site': 'same-origin',
        'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.6 Safari/605.1.15'
    }
    
    delay = retry_delay
    
    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                print(f"    Retrying in {delay:.1f} seconds... (attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                # Rate limited - retry with exponential backoff
                if attempt < max_retries:
                    continue
                else:
                    return {
                        "error": f"HTTP 429 (Rate Limited) - tried {max_retries + 1} times",
                        "status_code": 429,
                    }
            elif response.status_code == 400:
                # Address not registered
                try:
                    error_json = response.json()
                    if "not registered" in error_json.get("message", "").lower():
                        return {
                            "error": "Address not registered",
                            "status_code": 400,
                            "registered": False,
                        }
                except:
                    pass
                return {
                    "error": f"HTTP {response.status_code}",
                    "status_code": response.status_code,
                }
            else:
                return {
                    "error": f"HTTP {response.status_code}",
                    "status_code": response.status_code,
                    "text": response.text[:200],
                }
        except requests.exceptions.Timeout:
            if attempt < max_retries:
                continue
            return {
                "error": "Request timeout",
                "status_code": None,
            }
        except Exception as e:
            return {
                "error": str(e),
                "status_code": None,
            }
    
    return {
        "error": "Max retries exceeded",
        "status_code": None,
    }


def check_all_allocations(json_paths: List[str], output_file: str = "allocations_report.json", delay_between_requests: float = 1.0, no_skip: bool = False) -> None:
    """
    Check NIGHT allocations for all source addresses in the JSON files.
    
    Args:
        json_paths: List of paths to JSON files containing address lists
        output_file: Path to output file for the report
        delay_between_requests: Delay in seconds between API requests (default: 1.0)
        no_skip: If True, check all addresses without skipping (default: False)
    """
    print(f"Loading addresses from {len(json_paths)} file(s):")
    for path in json_paths:
        print(f"  - {path}")
    print()
    
    if no_skip:
        print("⚠️  Skipping optimization is DISABLED - all addresses will be checked")
        print()
    
    # Load all addresses from all files
    all_source_addresses: List[Dict] = []
    destinations: List[Dict] = []
    networks: List[str] = []
    file_sources: Dict[str, str] = {}  # Map address to source file
    
    for json_path in json_paths:
        with open(json_path, 'r') as f:
            address_data = json.load(f)
        
        network_str = address_data.get("network", "testnet")
        source_addresses = address_data.get("source_addresses", [])
        destination = address_data.get("destination", {})
        
        networks.append(network_str.upper())
        destinations.append({
            "file": json_path,
            "destination": destination,
        })
        
        # Add source file info to each address
        for addr_info in source_addresses:
            addr_info_with_source = addr_info.copy()
            addr_info_with_source["source_file"] = json_path
            all_source_addresses.append(addr_info_with_source)
            file_sources[addr_info.get("address", "")] = json_path
    
    # Check if all networks are the same
    unique_networks = list(set(networks))
    network_str = unique_networks[0] if len(unique_networks) == 1 else "MIXED"
    
    print(f"Network: {network_str}")
    print(f"Total source addresses to check: {len(all_source_addresses)}")
    print(f"Destinations: {len(destinations)}")
    for dest_info in destinations:
        dest_addr = dest_info["destination"].get("address", "N/A")
        print(f"  - {dest_addr} (from {dest_info['file']})")
    print()
    
    # Sort addresses by account, type, then by index for efficient checking
    # This allows us to skip remaining indices in an account/type combination if we find an unregistered address
    sorted_addresses = sorted(
        all_source_addresses,
        key=lambda x: (x.get("account", 0), x.get("type", "unknown"), x.get("index", 0))
    )
    
    # Results storage
    results: List[Dict] = []
    total_star = 0
    total_night = 0.0
    total_receipts = 0
    registered_count = 0
    error_count = 0
    
    # Track the skip threshold per account AND type
    # If we find an unregistered address at index N for account X, type Y,
    # we can skip all indices from N+1 up to (but not including) the next multiple of 50
    # We always check indices that are multiples of 50 (0, 50, 100, 150, etc.)
    # Key format: (account, type) -> skip_threshold (next multiple of 50)
    skip_threshold_per_account_type: Dict[tuple[int, str], int] = {}
    skipped_addresses = 0
    
    # Check each address
    for i, addr_info in enumerate(sorted_addresses, 1):
        address = addr_info.get("address")
        account = addr_info.get("account")
        index = addr_info.get("index")
        addr_type = addr_info.get("type", "unknown")
        source_file = addr_info.get("source_file", "unknown")
        
        if not address:
            print(f"[{i}/{len(sorted_addresses)}] ⚠️  Skipping entry with missing address")
            continue
        
        # Check if we should skip this address based on previous unregistered addresses
        # We track per account AND type, since staked and non-staked have separate index sequences
        # If we found an unregistered address at index N, we skip up to the next multiple of 50
        # We always check indices 0, 1, and all multiples of 50 (0, 50, 100, 150, etc.)
        # Skip logic can be disabled with the no_skip flag
        if not no_skip and account is not None and addr_type:
            account_type_key = (account, addr_type)
            skip_threshold = skip_threshold_per_account_type.get(account_type_key)
            
            # Check if we should skip this index
            # Skip if: there's a threshold AND current index is less than threshold AND 
            #          not a multiple of 50 AND not index 0 or 1 (always check 0 and 1)
            is_multiple_of_50 = (index % 50 == 0)
            is_always_check = (index == 0 or index == 1)
            if skip_threshold is not None and index < skip_threshold and not is_multiple_of_50 and not is_always_check:
                # Skip this index (we found an unregistered address earlier, skip until next multiple of 50)
                skipped_addresses += 1
                results.append({
                    "address": address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "source_file": source_file,
                    "registered": False,
                    "crypto_receipts": 0,
                    "night_allocation_star": 0,
                    "night_allocation_night": 0.0,
                    "error": f"Skipped (unregistered address found earlier, skipping to next multiple of 50)",
                    "skipped": True,
                })
                continue
        
        print(f"[{i}/{len(sorted_addresses)}] Checking: {address[:50]}...")
        print(f"    Account: {account}, Index: {index}, Type: {addr_type}")
        print(f"    Source: {source_file}")
        
        # Get statistics
        stats = get_address_statistics(address)
        
        # Parse results
        if "error" in stats:
            error_msg = stats.get("error", "Unknown error")
            status_code = stats.get("status_code")
            
            if status_code == 400 and "not registered" in error_msg.lower():
                print(f"    ⚠️  Address not registered")
                results.append({
                    "address": address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "source_file": source_file,
                    "registered": False,
                    "crypto_receipts": 0,
                    "night_allocation_star": 0,
                    "night_allocation_night": 0.0,
                    "error": "Not registered",
                })
                # Calculate the next multiple of 50 after this unregistered index
                # If we found unregistered at index N, we can skip up to (but not including) the next multiple of 50
                # Example: index 7 -> skip to 50, index 78 -> skip to 100
                # Only update skip threshold if skipping is enabled
                if not no_skip and account is not None and addr_type:
                    account_type_key = (account, addr_type)
                    # Calculate next multiple of 50: ((index // 50) + 1) * 50
                    next_multiple_of_50 = ((index // 50) + 1) * 50
                    
                    # Update skip threshold if this gives us a higher threshold
                    current_threshold = skip_threshold_per_account_type.get(account_type_key)
                    if current_threshold is None or next_multiple_of_50 > current_threshold:
                        skip_threshold_per_account_type[account_type_key] = next_multiple_of_50
                        print(f"    ℹ️  Skipping {addr_type} indices {index + 1} to {next_multiple_of_50 - 1} in account {account} (will check index {next_multiple_of_50})")
            elif status_code == 429:
                print(f"    ❌ Rate limited - stopping to avoid further rate limits")
                print(f"    💡 Wait a few minutes and run again, or reduce delay_between_requests")
                error_count += 1
                results.append({
                    "address": address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "source_file": source_file,
                    "error": "Rate limited",
                })
                break  # Stop checking to avoid more rate limits
            else:
                print(f"    ❌ Error: {error_msg}")
                error_count += 1
                results.append({
                    "address": address,
                    "account": account,
                    "index": index,
                    "type": addr_type,
                    "source_file": source_file,
                    "error": error_msg,
                })
        else:
            # Success - parse local data
            local_data = stats.get("local", {})
            crypto_receipts = local_data.get("crypto_receipts", 0)
            night_allocation_star = local_data.get("night_allocation", 0)
            night_allocation_night = night_allocation_star / 1_000_000
            
            print(f"    ✅ Registered: {crypto_receipts} receipts, {night_allocation_night:.6f} NIGHT ({night_allocation_star:,} STAR)")
            
            # If we found a registered address at a multiple of 50, clear the skip threshold
            # This allows us to continue checking normally after reaching the threshold
            # Only update skip threshold if skipping is enabled
            if not no_skip and account is not None and addr_type:
                account_type_key = (account, addr_type)
                is_multiple_of_50 = (index % 50 == 0)
                skip_threshold = skip_threshold_per_account_type.get(account_type_key)
                if is_multiple_of_50 and skip_threshold is not None and index >= skip_threshold:
                    # We've reached or passed the threshold and found a registered address
                    # Clear the threshold to continue checking normally
                    del skip_threshold_per_account_type[account_type_key]
                    print(f"    ℹ️  Reached skip threshold at index {index}, continuing normal checks")
            
            total_star += night_allocation_star
            total_night += night_allocation_night
            total_receipts += crypto_receipts
            registered_count += 1
            
            results.append({
                "address": address,
                "account": account,
                "index": index,
                "type": addr_type,
                "source_file": source_file,
                "registered": True,
                "crypto_receipts": crypto_receipts,
                "night_allocation_star": night_allocation_star,
                "night_allocation_night": night_allocation_night,
            })
        
        # Delay between requests to avoid rate limiting
        if i < len(sorted_addresses):
            time.sleep(delay_between_requests)
        
        print()
    
    # Generate JSON report
    print("=" * 80)
    print("Generating JSON report...")
    
    timestamp = datetime.now().isoformat()
    
    # Sort by allocation (highest first)
    registered_results = sorted(
        [r for r in results if r.get("registered")],
        key=lambda x: x.get("night_allocation_night", 0),
        reverse=True
    )
    
    # Separate unregistered/error addresses
    unregistered_results = [r for r in results if not r.get("registered") or "error" in r]
    
    # Build JSON report structure
    report = {
        "metadata": {
            "generated_at": timestamp,
            "source_files": json_paths,
            "network": network_str,
            "destinations": [
                {
                    "file": dest["file"],
                    "address": dest["destination"].get("address"),
                    "account": dest["destination"].get("account"),
                    "index": dest["destination"].get("index"),
                    "type": dest["destination"].get("type"),
                }
                for dest in destinations
            ]
        },
        "summary": {
            "total_addresses_checked": len(sorted_addresses),
            "addresses_skipped": skipped_addresses,
            "registered_addresses": registered_count,
            "unregistered_addresses": len(unregistered_results),
            "error_count": error_count,
            "total_solutions": total_receipts,
            "total_night_allocation_star": total_star,
            "total_night_allocation_night": round(total_night, 6),
        },
        "addresses": {
            "registered": registered_results,
            "unregistered": unregistered_results,
        }
    }
    
    # Write JSON file
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    # Print summary to console
    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)
    print(f"Files Processed: {len(json_paths)}")
    print(f"Total Addresses Checked: {len(sorted_addresses)}")
    print(f"Addresses Skipped (optimization): {skipped_addresses}")
    print(f"Registered Addresses: {registered_count}")
    print(f"Unregistered/Error Addresses: {len(sorted_addresses) - registered_count - error_count - skipped_addresses}")
    print(f"Errors: {error_count}")
    print()
    print(f"Total Solutions (crypto_receipts): {total_receipts:,}")
    print(f"Total NIGHT Allocation (STAR): {total_star:,} STAR")
    print(f"Total NIGHT Allocation (NIGHT): {total_night:.6f} NIGHT")
    print()
    print(f"✅ JSON report saved to: {output_file}")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(
        description="Check NIGHT allocations for all addresses in a JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check all addresses from a single JSON file
  python check_all_allocations.py --addresses addresses_enterprise.json
  
  # Check addresses from multiple JSON files
  python check_all_allocations.py --addresses addresses_enterprise.json addresses_staked.json
  
  # Specify custom output file
  python check_all_allocations.py --addresses addresses_enterprise.json --output my_allocations.json
  
  # Multiple files with custom output
  python check_all_allocations.py --addresses addresses_enterprise.json addresses_staked.json --output combined_allocations.json
  
  # Reduce delay between requests (faster but more likely to hit rate limits)
  python check_all_allocations.py --addresses addresses_enterprise.json --delay 0.5
  
  # Check all addresses without skipping (disable optimization)
  python check_all_allocations.py --addresses addresses_enterprise.json --no-skip
        """
    )
    
    parser.add_argument(
        "--addresses",
        type=str,
        nargs='+',
        required=True,
        help="Path(s) to JSON file(s) containing address list (can specify multiple files)",
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default="allocations_report.json",
        help="Output file for the JSON report (default: allocations_report.json)",
    )
    
    parser.add_argument(
        "--delay",
        type=float,
        default=1.0,
        help="Delay in seconds between API requests (default: 1.0, increase if rate limited)",
    )
    
    parser.add_argument(
        "--no-skip",
        action="store_true",
        help="Disable skipping optimization - check all addresses regardless of unregistered addresses found",
    )
    
    args = parser.parse_args()
    
    try:
        check_all_allocations(
            json_paths=args.addresses,
            output_file=args.output,
            delay_between_requests=args.delay,
            no_skip=args.no_skip,
        )
    except KeyboardInterrupt:
        print("\n\nInterrupted by user")
    except FileNotFoundError as e:
        print(f"\n\nError: Address file not found: {e}")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

