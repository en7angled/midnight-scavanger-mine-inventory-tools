# NIGHT Token Consolidation Scripts

> **If you are an ADA holder please delegate to: E7D ([pool1sj3gnahsms73uxxu43rgwczdw596en7dtsfcqf6297vzgcedquv](https://cexplorer.io/pool/pool1sj3gnahsms73uxxu43rgwczdw596en7dtsfcqf6297vzgcedquv))**

These scripts help you manage and consolidate NIGHT tokens from multiple Cardano addresses into a single destination address using the Scavenger Mine API.

## Overview

The toolkit consists of the following scripts:

**Main Workflow Scripts:**
1. **`generate_addresses.py`** - Generates JSON files containing addresses derived from your mnemonic (supports both staked and non-staked addresses)
2. **`check_all_allocations.py`** - Check all addresses from JSON files and generate a comprehensive allocation report
3. **`breakdown_allocations.py`** - Generate breakdown per account and total from allocation reports
4. **`consolidate_night.py`** - Consolidate tokens from multiple addresses into a destination address

**Additional Tools:**
5. **`check_address_status.py`** - Check individual address status, allocations, and solutions
6. **`calculate_gains.py`** - Calculate gains between baseline and current allocation reports

## Features

- ✅ Derives Cardano addresses from a BIP39 mnemonic phrase (CIP-1852 and BIP44)
- ✅ Supports both staked (`addr1q`) and non-staked (`addr1v`) addresses
- ✅ Check NIGHT allocations and solutions for addresses
- ✅ Generate comprehensive allocation reports (JSON format)
- ✅ Generate donation URLs for manual consolidation
- ✅ Handles CIP-30 signatures required by the API

## Installation

1. **Create a virtual environment** (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

2. **Install dependencies**:
```bash
pip install -r requirements.txt
```

**Note**: If you encounter issues with `coincurve` (from `bip-utils`), you can install just the required packages:
```bash
pip install requests pycardano
```

## Quick Start - Main Workflow

Follow these steps to consolidate your NIGHT tokens:

### Step 1: Generate Addresses

Generate JSON files with addresses derived from your mnemonic phrase:

```bash
python generate_addresses.py \
  --mnemonic "word1 word2 word3 ... word24" \
  --accounts 0 1 2 3 4 \
  --include-enterprise \
  --mainnet
```

This creates:
- `addresses_staked.json` - Staked addresses (`addr1q...`)
- `addresses_enterprise.json` - Non-staked addresses (`addr1v...`)

### Step 2: Check Allocations

Check all addresses and generate an allocation report:

```bash
python check_all_allocations.py \
  --addresses addresses_enterprise.json addresses_staked.json \
  --output allocations_report.json
```

This generates `allocations_report.json` with:
- All registered addresses
- NIGHT allocations per address
- Solutions count per address
- Summary totals

### Step 2.1: Generate Breakdown (Optional)

Generate a breakdown per account and total from the allocation report:

```bash
python breakdown_allocations.py \
  --reports allocations_report.json
```

This shows:
- Total breakdown (NIGHT, solutions, addresses)
- Breakdown by account (staked vs non-staked)
- Detailed per-account statistics

### Step 3: Consolidate

Consolidate NIGHT tokens using the allocation report:

**Option A: Execute consolidations directly (recommended)**
```bash
python consolidate_night.py \
  --addresses allocations_report.json \
  --mnemonic "word1 word2 ... word24"
```

This will:
- Process all addresses with NIGHT allocations > 0
- Execute consolidations automatically
- Generate `consolidation_report.json` with results

**Option B: Generate bash script for manual review**
```bash
python consolidate_night.py \
  --addresses allocations_report.json \
  --mnemonic "word1 word2 ... word24" \
  --generate-commands \
  --output consolidation_commands.sh
```

Then review and execute:
```bash
# Review the commands
cat consolidation_commands.sh

# Execute all commands
bash consolidation_commands.sh
```

### Review Results

Check the consolidation report:
```bash
cat consolidation_report.json | python -m json.tool | less
```

The report includes:
- Summary (successful, already consolidated, failed, errors)
- Totals per destination address
- Detailed list of all consolidations

## Scripts Overview

### 1. generate_addresses.py

Generates JSON files with addresses derived from your mnemonic phrase.

**Basic Usage:**
```bash
python generate_addresses.py \
  --mnemonic "word1 word2 word3 ... word24" \
  --accounts 0 1 2 3 4 \
  -o addresses.json
```

**Generate both staked and non-staked addresses:**
```bash
python generate_addresses.py \
  --mnemonic "word1 ... word24" \
  --accounts 0 1 2 3 4 \
  --include-enterprise \
  --mainnet
```

This creates two files:
- `addresses_staked.json` - Staked addresses (`addr1q...`)
- `addresses_enterprise.json` - Non-staked addresses (`addr1v...`)

**Options:**
- `--mnemonic` (required): Your BIP39 mnemonic phrase
- `--accounts` (required): Space-separated list of account numbers
- `--destination-account`: Account for destination address (default: 0)
- `--destination-index`: Index for destination address (default: 0)
- `--max-index`: Maximum address index per account (default: 10)
- `--include-enterprise`: Generate non-staked addresses in separate file
- `--mainnet`: Use Cardano mainnet (default: testnet)
- `-o, --output`: Output JSON file path

### 2. check_address_status.py

Check the status of a single address, including NIGHT allocation and solutions.

**Usage:**
```bash
# Check by address
python check_address_status.py --address "addr1q..."

# Check by mnemonic derivation
python check_address_status.py \
  --mnemonic "word1 ... word24" \
  --account 0 \
  --index 0 \
  --mainnet
```

**Output includes:**
- Solutions produced (crypto_receipts)
- NIGHT allocation in STAR and NIGHT
- Global network statistics

**Options:**
- `--address`: Directly provide address
- `--mnemonic`: Derive address from mnemonic
- `--account`: Account number (required with --mnemonic)
- `--index`: Address index (default: 0)
- `--mainnet`: Use mainnet (default: testnet)
- `--bip44`: Use BIP44 instead of CIP-1852

### 3. check_all_allocations.py

Check NIGHT allocations for all addresses in one or more JSON files and generate a comprehensive report.

**Usage:**
```bash
# Single file
python check_all_allocations.py --addresses addresses_enterprise.json

# Multiple files
python check_all_allocations.py \
  --addresses addresses_enterprise.json addresses_staked.json \
  --output combined_allocations.json
```

**Features:**
- Checks all addresses from JSON files
- Generates JSON report with detailed breakdown
- Optimized checking: skips higher indices when unregistered addresses found (indices 0-50 always checked)
- Tracks separately by account and type (staked vs non-staked)
- Includes summary totals and per-address details

**Options:**
- `--addresses` (required): One or more JSON file paths
- `--output`: Output JSON file (default: allocations_report.json)
- `--delay`: Delay between API requests in seconds (default: 1.0)

**Allocation Report Structure:**
```json
{
  "metadata": {
    "generated_at": "...",
    "source_files": [...],
    "network": "MAINNET",
    "destinations": [...]
  },
  "summary": {
    "total_addresses_checked": 3617,
    "addresses_skipped": 3034,
    "registered_addresses": 565,
    "total_solutions": 9585,
    "total_night_allocation_night": 18318.710148
  },
  "addresses": {
    "registered": [...],
    "unregistered": [...]
  }
}
```

**Consolidation Report Structure** (generated by `consolidate_night.py`):
```json
{
  "metadata": {
    "generated_at": "...",
    "source_file": "allocations_report.json",
    "destination_address": "addr1q...",
    "total_addresses": 565
  },
  "summary": {
    "successful": 450,
    "already_consolidated": 100,
    "failed": 10,
    "errors": 5
  },
  "destination_totals": {
    "addr1q...": {
      "night": 15000.123456,
      "solutions": 5000,
      "count": 550
    }
  },
  "consolidations": {
    "successful": [...],
    "already_consolidated": [...],
    "failed": [...],
    "errors": [...]
  }
}
```

### 4. consolidate_night.py

Consolidate NIGHT tokens from multiple addresses into a single destination address.

**Important**: This script only works with allocation reports (from `check_all_allocations.py`). It automatically filters to only process addresses with NIGHT allocations > 0.

**Execute consolidations directly (default):**
```bash
python consolidate_night.py \
  --addresses allocations_report.json \
  --mnemonic "word1 ... word24"
```

**Generate bash script with commands (for manual review):**
```bash
python consolidate_night.py \
  --addresses allocations_report.json \
  --mnemonic "word1 ... word24" \
  --generate-commands \
  --output consolidation_commands.sh
```

**Options:**
- `--addresses` (required): Path to allocation report JSON file (from `check_all_allocations.py`)
- `--mnemonic` (required): BIP39 mnemonic phrase
- `--report`: Output file for consolidation report (default: `consolidation_report.json`, only used when executing)
- `--delay`: Delay between requests in seconds (default: 1.0, only used when executing)
- `--generate-commands`: Generate bash script with commands instead of executing consolidations
- `--output`: Output file for bash script (default: `consolidation_commands.sh`, only used with `--generate-commands`)

**Features:**
- Only processes addresses with NIGHT allocations > 0
- Automatically verifies 409 responses to check if destination matches
- Generates detailed consolidation report with totals per destination
- Tracks successful, already consolidated, failed, and error cases
- Shows real-time progress during execution

## Additional Scripts

### breakdown_allocations.py

Generate a breakdown per account and total from allocation reports.

**Usage:**
```bash
# Single report
python breakdown_allocations.py --reports allocations_report.json

# Multiple reports
python breakdown_allocations.py \
  --reports allocations_report1.json allocations_report2.json
```

**Output:**
- Total breakdown (NIGHT, solutions, addresses)
- Breakdown by account (staked vs non-staked)
- Detailed per-account statistics with percentages

### calculate_gains.py

Calculate gains between baseline and current allocation reports.

**Usage:**
```bash
python calculate_gains.py \
  --baseline baseline_report1.json baseline_report2.json \
  --current current_report1.json current_report2.json \
  --output gains.json
```

**Output:**
- Total gains (NIGHT, solutions, addresses)
- Gains by account (staked vs non-staked)
- Detailed per-account breakdown

## JSON File Format

The generated JSON files have the following structure:

```json
{
  "network": "mainnet",
  "use_cip1852": true,
  "destination": {
    "address": "addr1q...",
    "account": 0,
    "index": 0,
    "type": "staked"
  },
  "source_addresses": [
    {
      "address": "addr1q...",
      "account": 0,
      "index": 0,
      "type": "staked"
    },
    {
      "address": "addr1v...",
      "account": 0,
      "index": 0,
      "type": "non-staked"
    }
  ]
}
```

## How It Works

### Address Derivation

The scripts support both derivation methods:
- **CIP-1852** (default): `m/1852'/1815'/account'/0/index` - Used by modern wallets (Eternl, Daedalus, Yoroi)
- **BIP44** (legacy): `m/44'/1815'/account'/0/index` - Legacy derivation

### Address Types

- **Staked addresses** (`addr1q...`): Base addresses with staking capability
- **Non-staked addresses** (`addr1v...`): Enterprise addresses without staking

### Consolidation Process

1. For each source address (with NIGHT allocations > 0):
   - Derives signing key from mnemonic
   - Signs message: `"Assign accumulated Scavenger rights to: {destination_address}"`
   - Creates COSE_Sign1 signature (CBOR format)
   - Calls API: `POST /donate_to/{destination}/{original}/{signature}`

2. The API endpoint format:
   - URL: `/donate_to/{destination_address}/{original_address}/{signature}`
   - Only the original address needs to sign
   - Message format: `"Assign accumulated Scavenger rights to: {destination_address}"`
   - Signature format: COSE_Sign1 (CBOR-encoded)

3. Response handling:
   - **200 OK**: Successfully consolidated
   - **409 Conflict**: Already consolidated - script verifies destination matches
   - **404 Not Found**: Address not registered or has no rewards
   - **Other errors**: Tracked in report

4. Report generation:
   - Summary of successful, already consolidated, failed, and errors
   - Totals per destination address (NIGHT, solutions, count)
   - Detailed list of all consolidations with status and amounts

### Allocation Checking

The `check_all_allocations.py` script:
- Sorts addresses by account, type, then index
- Checks addresses in order
- For indices 0-50: Always checks (no skipping)
- For indices > 50: Skips higher indices if lower index is unregistered
- Tracks separately for staked vs non-staked addresses

## API Endpoints

### Scavenger Mine API
- **Base URL**: `https://scavenger.prod.gd.midnighttge.io`
- **Donate Endpoint**: `POST /donate_to/{destination}/{original}/{signature}`
- **Terms & Conditions**: `GET /TandC`
- **Register**: `POST /register`

### Browser API (for status checks)
- **Base URL**: `https://sm.midnight.gd/api`
- **Statistics**: `GET /statistics/{address}`
  - Returns: `local.crypto_receipts` (solutions) and `local.night_allocation` (STAR)
  - 1 NIGHT = 1,000,000 STAR
  - Updates every 24 hours

## Security Notes

⚠️ **Important Security Considerations:**

- **Never share your mnemonic phrase** with anyone
- Run these scripts on a **secure, trusted machine**
- Consider using a **hardware wallet** for better security
- **Review the code** before running it with your real mnemonic
- The JSON files contain **addresses only** (not private keys)
- Private keys are derived on-the-fly from mnemonic when needed
- **Backup your mnemonic** in a secure location

## Troubleshooting

### "Address not registered"
- The address hasn't been registered in Scavenger Mine
- Normal for addresses that haven't participated in mining
- Scripts will skip these automatically

### "HTTP 403 Forbidden" on consolidation
- Address may not have rewards to consolidate
- Address must have submitted solutions (not just registered)
- Check address status first with `check_address_status.py`
- Note: Script automatically filters to only process addresses with NIGHT allocations > 0

### "HTTP 409 Conflict" on consolidation
- Address is already consolidated
- Script automatically verifies if destination matches
- If destination matches: Counted as "already consolidated" in report
- If destination differs: Marked as failed with both intended and actual destinations

### "HTTP 429 Rate Limited"
- API is rate-limiting requests
- Increase `--delay` in `check_all_allocations.py`
- Wait a few minutes and try again
- Browser API is less likely to be rate-limited

### "Address file not found" or "File does not appear to be an allocation report"
- `consolidate_night.py` requires an allocation report from `check_all_allocations.py`
- Generate the allocation report first: `python check_all_allocations.py --addresses addresses.json`
- The script only works with allocation reports, not raw address lists

### Addresses don't match your wallet
- Your wallet may use CIP-1852 (default) or BIP44
- Scripts default to CIP-1852
- Use `--bip44` flag if needed
- Verify derivation path matches your wallet

### Virtual environment issues
- Always activate virtual environment: `source venv/bin/activate`
- If `coincurve` fails, install only: `pip install requests pycardano`

## Analyzing Allocation Reports

To get totals by address type from the JSON report:

```bash
python3 -c "
import json
with open('allocations_report.json', 'r') as f:
    report = json.load(f)
registered = report['addresses']['registered']
staked = [a for a in registered if a['type'] == 'staked']
non_staked = [a for a in registered if a['type'] == 'non-staked']
print(f'Staked: {sum(a[\"night_allocation_night\"] for a in staked):.6f} NIGHT')
print(f'Non-staked: {sum(a[\"night_allocation_night\"] for a in non_staked):.6f} NIGHT')
"
```

## License

These scripts are provided as-is for educational and personal use.

## References

- [Scavenger Mine API V2 Documentation](https://45047878.fs1.hubspotusercontent-na1.net/hubfs/45047878/Midnight%20-%20Whitepaper%20treatment%20for%20Scavenger%20Mine%20API%20V2.pdf)
- [CIP-1852 Specification](https://cips.cardano.org/cips/cip1852/)
- [BIP44 Specification](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
