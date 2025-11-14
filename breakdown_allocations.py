#!/usr/bin/env python3
"""
Breakdown Allocations Script

This script reads allocation report JSON files and generates a breakdown
showing totals and per-account statistics.
"""

import json
import argparse
from collections import defaultdict
from typing import Dict, List


def load_reports(json_paths: List[str]) -> tuple[Dict, List[Dict]]:
    """
    Load allocation reports from JSON files.
    
    Args:
        json_paths: List of paths to JSON report files
        
    Returns:
        Tuple of (combined_summary, all_registered_addresses)
    """
    all_registered = []
    combined_summary = {
        "total_addresses_checked": 0,
        "addresses_skipped": 0,
        "registered_addresses": 0,
        "unregistered_addresses": 0,
        "error_count": 0,
        "total_solutions": 0,
        "total_night_allocation_star": 0,
        "total_night_allocation_night": 0.0,
    }
    
    for json_path in json_paths:
        print(f"Loading: {json_path}")
        with open(json_path, 'r') as f:
            data = json.load(f)
        
        summary = data.get("summary", {})
        registered = data.get("addresses", {}).get("registered", [])
        
        # Combine summaries
        combined_summary["total_addresses_checked"] += summary.get("total_addresses_checked", 0)
        combined_summary["addresses_skipped"] += summary.get("addresses_skipped", 0)
        combined_summary["registered_addresses"] += summary.get("registered_addresses", 0)
        combined_summary["unregistered_addresses"] += summary.get("unregistered_addresses", 0)
        combined_summary["error_count"] += summary.get("error_count", 0)
        combined_summary["total_solutions"] += summary.get("total_solutions", 0)
        combined_summary["total_night_allocation_star"] += summary.get("total_night_allocation_star", 0)
        combined_summary["total_night_allocation_night"] += summary.get("total_night_allocation_night", 0.0)
        
        all_registered.extend(registered)
    
    return combined_summary, all_registered


def calculate_breakdown(registered_addresses: List[Dict]) -> Dict[int, Dict]:
    """
    Calculate per-account breakdown with staked vs non-staked separation.
    
    Args:
        registered_addresses: List of registered address dictionaries
        
    Returns:
        Dictionary mapping account number to account statistics
    """
    account_stats = defaultdict(lambda: {
        "address_count": 0,
        "staked_address_count": 0,
        "non_staked_address_count": 0,
        "total_solutions": 0,
        "total_night_star": 0,
        "total_night_night": 0.0,
        "staked_night_star": 0,
        "staked_night_night": 0.0,
        "non_staked_night_star": 0,
        "non_staked_night_night": 0.0,
        "addresses": []
    })
    
    for addr in registered_addresses:
        account = addr.get("account")
        if account is None:
            continue
        
        addr_type = addr.get("type", "").lower()
        is_staked = addr_type in ["staked", "base"]
        is_non_staked = addr_type in ["non-staked", "enterprise", "non_staked"]
        
        night_night = addr.get("night_allocation_night", 0.0)
        night_star = addr.get("night_allocation_star", 0)
        
        account_stats[account]["address_count"] += 1
        account_stats[account]["total_solutions"] += addr.get("crypto_receipts", 0)
        account_stats[account]["total_night_star"] += night_star
        account_stats[account]["total_night_night"] += night_night
        
        if is_staked:
            account_stats[account]["staked_address_count"] += 1
            account_stats[account]["staked_night_star"] += night_star
            account_stats[account]["staked_night_night"] += night_night
        elif is_non_staked:
            account_stats[account]["non_staked_address_count"] += 1
            account_stats[account]["non_staked_night_star"] += night_star
            account_stats[account]["non_staked_night_night"] += night_night
        
        account_stats[account]["addresses"].append(addr)
    
    return dict(account_stats)


def print_breakdown(combined_summary: Dict, account_breakdown: Dict[int, Dict]) -> None:
    """
    Print the breakdown to console.
    
    Args:
        combined_summary: Combined summary statistics
        account_breakdown: Per-account breakdown dictionary
    """
    print("=" * 80)
    print("ALLOCATION BREAKDOWN")
    print("=" * 80)
    print()
    
    # Total breakdown
    print("📊 TOTAL BREAKDOWN")
    print("-" * 80)
    print(f"Total Addresses Checked: {combined_summary['total_addresses_checked']:,}")
    print(f"Addresses Skipped: {combined_summary['addresses_skipped']:,}")
    print(f"Registered Addresses: {combined_summary['registered_addresses']:,}")
    print(f"Unregistered Addresses: {combined_summary['unregistered_addresses']:,}")
    print(f"Errors: {combined_summary['error_count']:,}")
    print()
    print(f"Total Solutions (crypto_receipts): {combined_summary['total_solutions']:,}")
    print(f"Total NIGHT Allocation (STAR): {combined_summary['total_night_allocation_star']:,} STAR")
    print(f"Total NIGHT Allocation (NIGHT): {combined_summary['total_night_allocation_night']:,.6f} NIGHT")
    print()
    
    # Per-account breakdown table
    print("=" * 80)
    print("BREAKDOWN BY ACCOUNT")
    print("=" * 80)
    print()
    
    # Sort accounts by account number
    sorted_accounts = sorted(account_breakdown.items())
    
    # Print table header
    print(f"{'Account':<10} {'Staked (NIGHT)':<18} {'Non-staked (NIGHT)':<20} {'Total (NIGHT)':<18} {'Addresses':<12}")
    print("-" * 80)
    
    # Print table rows
    for account, stats in sorted_accounts:
        staked_night = stats['staked_night_night']
        non_staked_night = stats['non_staked_night_night']
        total_night = stats['total_night_night']
        address_count = stats['address_count']
        
        print(f"{account:<10} {staked_night:<18,.2f} {non_staked_night:<20,.2f} {total_night:<18,.2f} {address_count:<12,}")
    
    print("=" * 80)
    print()
    
    # Detailed per-account breakdown
    print("=" * 80)
    print("DETAILED PER-ACCOUNT BREAKDOWN")
    print("=" * 80)
    print()
    
    for account, stats in sorted_accounts:
        print(f"Account {account}")
        print("-" * 80)
        print(f"  Total Addresses: {stats['address_count']:,}")
        print(f"    - Staked: {stats['staked_address_count']:,}")
        print(f"    - Non-staked: {stats['non_staked_address_count']:,}")
        print(f"  Total Solutions: {stats['total_solutions']:,}")
        print(f"  Staked NIGHT: {stats['staked_night_night']:,.6f} NIGHT ({stats['staked_night_star']:,} STAR)")
        print(f"  Non-staked NIGHT: {stats['non_staked_night_night']:,.6f} NIGHT ({stats['non_staked_night_star']:,} STAR)")
        print(f"  Total NIGHT: {stats['total_night_night']:,.6f} NIGHT ({stats['total_night_star']:,} STAR)")
        print(f"  Percentage of Total: {(stats['total_night_night'] / combined_summary['total_night_allocation_night'] * 100):.2f}%")
        print()
    
    print("=" * 80)


def save_breakdown_json(combined_summary: Dict, account_breakdown: Dict[int, Dict], output_file: str) -> None:
    """
    Save breakdown to JSON file.
    
    Args:
        combined_summary: Combined summary statistics
        account_breakdown: Per-account breakdown dictionary
        output_file: Path to output JSON file
    """
    # Convert account numbers to strings for JSON serialization
    account_breakdown_json = {
        str(account): {
            "address_count": stats["address_count"],
            "staked_address_count": stats["staked_address_count"],
            "non_staked_address_count": stats["non_staked_address_count"],
            "total_solutions": stats["total_solutions"],
            "staked_night_allocation_star": stats["staked_night_star"],
            "staked_night_allocation_night": round(stats["staked_night_night"], 6),
            "non_staked_night_allocation_star": stats["non_staked_night_star"],
            "non_staked_night_allocation_night": round(stats["non_staked_night_night"], 6),
            "total_night_allocation_star": stats["total_night_star"],
            "total_night_allocation_night": round(stats["total_night_night"], 6),
            "percentage_of_total": round((stats["total_night_night"] / combined_summary["total_night_allocation_night"] * 100), 2) if combined_summary["total_night_allocation_night"] > 0 else 0,
        }
        for account, stats in account_breakdown.items()
    }
    
    report = {
        "total": combined_summary,
        "by_account": account_breakdown_json,
    }
    
    with open(output_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"✅ JSON breakdown saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Generate breakdown of allocations from report JSON files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Breakdown from single report
  python breakdown_allocations.py --reports sun_allocations_report1.json
  
  # Breakdown from multiple reports
  python breakdown_allocations.py --reports sun_allocations_report1.json sun_allocations_report2.json
  
  # Save to JSON file
  python breakdown_allocations.py --reports sun_allocations_report1.json sun_allocations_report2.json --output breakdown.json
        """
    )
    
    parser.add_argument(
        "--reports",
        type=str,
        nargs='+',
        required=True,
        help="Path(s) to JSON report file(s) (can specify multiple files)",
    )
    
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Optional: Save breakdown to JSON file",
    )
    
    args = parser.parse_args()
    
    try:
        # Load reports
        combined_summary, all_registered = load_reports(args.reports)
        
        # Calculate breakdown
        account_breakdown = calculate_breakdown(all_registered)
        
        # Print breakdown
        print_breakdown(combined_summary, account_breakdown)
        
        # Save to JSON if requested
        if args.output:
            save_breakdown_json(combined_summary, account_breakdown, args.output)
        
    except FileNotFoundError as e:
        print(f"\n\nError: Report file not found: {e}")
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    main()

