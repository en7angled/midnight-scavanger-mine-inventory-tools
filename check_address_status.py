#!/usr/bin/env python3
"""
Check Address Status Script

This script checks the status of an address in Scavenger Mine,
including NIGHT allocation, solutions produced, and miner status.
Uses the browser API endpoint: https://sm.midnight.gd/api/statistics/{address}

The API returns a 'local' object containing:
- crypto_receipts: Number of solutions produced for the address
- night_allocation: NIGHT allocation in STAR (1 NIGHT = 1,000,000 STAR)
  Note: night_allocation updates every 24 hours
"""

import argparse
import json
import time
import requests
from consolidate_night import derive_address_from_mnemonic
from pycardano import Network

# Browser API base URL (different from the mining API)
BROWSER_API_BASE_URL = "https://sm.midnight.gd/api"


def get_address_statistics(address: str, max_retries: int = 3, retry_delay: float = 2.0, cookies: dict = None) -> dict:
    """
    Get statistics for an address from the browser API.
    
    Args:
        address: Cardano address to check
        max_retries: Maximum number of retries on rate limit (default: 3)
        retry_delay: Initial delay between retries in seconds (default: 2.0)
        cookies: Optional dictionary of cookies to use (from browser session)
    
    Returns:
        Dictionary with statistics data
    
    Note: Browsers aren't rate-limited because they:
        - Have session cookies from visiting the website
        - Have proper TLS fingerprints
        - Execute JavaScript (creating browser context)
        - Make naturally spaced requests
    Scripts can be rate-limited because they lack these characteristics.
    To reduce rate limiting, you can:
        - Copy cookies from your browser's Developer Tools
        - Use browser automation (Selenium/Playwright)
        - Add longer delays between requests
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
    
    # Use cookies if provided (from browser session)
    session = requests.Session()
    if cookies:
        session.cookies.update(cookies)
    
    delay = retry_delay
    
    for attempt in range(max_retries + 1):
        try:
            # Add a small delay before each request to avoid rapid-fire requests
            if attempt > 0:
                print(f"  Retrying in {delay:.1f} seconds... (attempt {attempt + 1}/{max_retries + 1})")
                time.sleep(delay)
                delay *= 2  # Exponential backoff
            
            response = session.get(url, headers=headers, timeout=10)
            
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
                        "text": "Rate limited. Please wait a few minutes and try again, or use the browser interface.",
                    }
            else:
                error_text = response.text[:500]
                try:
                    error_json = response.json()
                    return {
                        "error": f"HTTP {response.status_code}",
                        "status_code": response.status_code,
                        "text": error_text,
                        "details": error_json,
                    }
                except:
                    return {
                        "error": f"HTTP {response.status_code}",
                        "status_code": response.status_code,
                        "text": error_text,
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


def main():
    parser = argparse.ArgumentParser(
        description="Check Scavenger Mine address status (estimated claims, solutions, etc.)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--mnemonic",
        type=str,
        help="BIP39 mnemonic phrase (required if --address not provided)",
    )
    
    parser.add_argument(
        "--account",
        type=int,
        help="Account number (required if --address not provided)",
    )
    
    parser.add_argument(
        "--index",
        type=int,
        default=0,
        help="Address index (default: 0)",
    )
    
    parser.add_argument(
        "--mainnet",
        action="store_true",
        help="Use mainnet (default: testnet)",
    )
    
    parser.add_argument(
        "--bip44",
        action="store_true",
        help="Use BIP44 derivation instead of CIP-1852",
    )
    
    parser.add_argument(
        "--address",
        type=str,
        help="Directly provide address (skips derivation)",
    )
    
    args = parser.parse_args()
    
    # Use provided address or derive from mnemonic
    if args.address:
        address = args.address
        print(f"Using provided address: {address}")
    else:
        # Validate required arguments for derivation
        if not args.mnemonic:
            parser.error("Either --mnemonic (with --account) or --address must be provided")
        if args.account is None:
            parser.error("--account is required when deriving from mnemonic")
        
        network = Network.MAINNET if args.mainnet else Network.TESTNET
        use_cip1852 = not args.bip44
        
        # Derive address
        address, _ = derive_address_from_mnemonic(
            args.mnemonic, args.account, args.index, network, use_cip1852
        )
    
    print(f"Checking status for address:")
    if not args.address:
        print(f"  Account: {args.account}, Index: {args.index}")
        print(f"  Network: {network}")
    print(f"  Address: {address}")
    print()
    
    # Get statistics
    print("=" * 60)
    stats = get_address_statistics(address)
    
    if "error" in stats:
        print(f"❌ Error: {stats['error']}")
        if stats.get('details'):
            print(f"  Details: {json.dumps(stats['details'], indent=2)}")
        elif stats.get('text'):
            print(f"  Response: {stats['text']}")
        if stats.get('status_code') == 429:
            print("  💡 The API is rate-limited to prevent abuse.")
            print("     Options:")
            print("     1. Wait 1-2 minutes and try again")
            print("     2. Use the browser interface at https://sm.midnight.gd/wizard/mine")
            print("     3. Make fewer requests (the script will retry automatically)")
        elif stats.get('status_code') == 403:
            print("  Access forbidden - endpoint may require authentication")
    else:
        print("✅ Address Statistics:")
        print(json.dumps(stats, indent=2))
        
        # Extract key information
        if isinstance(stats, dict):
            print()
            print("=" * 60)
            print("Summary:")
            
            # Parse local object (contains crypto_receipts and night_allocation)
            local_data = stats.get("local", {})
            if local_data:
                crypto_receipts = local_data.get("crypto_receipts", 0)
                night_allocation_star = local_data.get("night_allocation", 0)
                night_allocation_night = night_allocation_star / 1_000_000
                
                print(f"  Solutions Produced (crypto_receipts): {crypto_receipts:,}")
                print(f"  NIGHT Allocation (STAR): {night_allocation_star:,} STAR")
                print(f"  NIGHT Allocation (NIGHT): {night_allocation_night:.6f} NIGHT")
            
            # Also show other fields if present
            if "estimatedClaim" in stats or "estimated_claim" in stats:
                claim = stats.get("estimatedClaim") or stats.get("estimated_claim")
                print(f"  Estimated Claim: {claim} NIGHT")
            if "submittedSolutions" in stats or "submitted_solutions" in stats:
                solutions = stats.get("submittedSolutions") or stats.get("submitted_solutions")
                print(f"  Submitted Solutions: {solutions}")
            if "minerStatus" in stats or "miner_status" in stats:
                status = stats.get("minerStatus") or stats.get("miner_status")
                print(f"  Miner Status: {status}")
            if "estimatedShare" in stats or "estimated_share" in stats:
                share = stats.get("estimatedShare") or stats.get("estimated_share")
                print(f"  Estimated Share: {share}")
            
            # Note about updates
            if local_data:
                print()
                print("  ℹ️  Note: night_allocation updates every 24 hours")
                print("  ℹ️  Note: 1 NIGHT = 1,000,000 STAR")
    print("=" * 60)


if __name__ == "__main__":
    main()

