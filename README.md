# NIGHT Token Consolidation Scripts

These scripts help you manage and consolidate NIGHT tokens from multiple Cardano addresses into a single destination address using the Scavenger Mine API.

## Overview

The toolkit consists of four main scripts:

1. **`generate_addresses.py`** - Generates JSON files containing addresses derived from your mnemonic (supports both staked and non-staked addresses)
2. **`check_address_status.py`** - Check individual address status, allocations, and solutions
3. **`check_all_allocations.py`** - Check all addresses from JSON files and generate a comprehensive allocation report
4. **`consolidate_night.py`** - Consolidate tokens from multiple addresses into a destination address

## Features

- ✅ Derives Cardano addresses from a BIP39 mnemonic phrase (CIP-1852 and BIP44)
- ✅ Supports both staked (`addr1q`) and non-staked (`addr1v`) addresses
- ✅ Check NIGHT allocations and solutions for addresses
- ✅ Generate comprehensive allocation reports (JSON format)
- ✅ Consolidate rewards from multiple accounts/addresses into one
- ✅ Generate donation URLs for manual consolidation
- ✅ Handles CIP-30 signatures required by the API
- ✅ Supports both testnet and mainnet
- ✅ Smart optimization: skips higher indices when unregistered addresses are found (indices 0-50 always checked)
- ✅ Provides clear progress feedback and error handling

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

**Report Structure:**
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

### 4. consolidate_night.py

Consolidate NIGHT tokens from multiple addresses into a single destination address.

**Basic Usage:**
```bash
python consolidate_night.py \
  --addresses addresses.json \
  --mnemonic "word1 ... word24"
```

**Generate donation URLs (for manual consolidation):**
```bash
python consolidate_night.py \
  --addresses addresses.json \
  --mnemonic "word1 ... word24" \
  --generate-urls \
  --url-output my_donation_urls.txt
```

**Options:**
- `--addresses` (required): Path to JSON file with address list
- `--mnemonic` (required): BIP39 mnemonic phrase
- `--generate-urls`: Generate HTTPS URLs instead of consolidating
- `--url-output`: Output file for URLs (default: donation_urls.txt)

## Complete Workflow Example

```bash
# 1. Generate addresses (both staked and non-staked)
python generate_addresses.py \
  --mnemonic "your mnemonic phrase here" \
  --accounts 0 1 2 3 4 \
  --include-enterprise \
  --mainnet

# 2. Check allocations for all addresses
python check_all_allocations.py \
  --addresses addresses_enterprise.json addresses_staked.json \
  --output allocations_report.json

# 3. Review the report
cat allocations_report.json | python -m json.tool | less

# 4. Consolidate tokens
python consolidate_night.py \
  --addresses addresses_staked.json \
  --mnemonic "your mnemonic phrase here"

# OR generate URLs for manual consolidation
python consolidate_night.py \
  --addresses addresses_staked.json \
  --mnemonic "your mnemonic phrase here" \
  --generate-urls
```

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

1. For each source address:
   - Derives signing key from mnemonic
   - Signs message: `{destination_address}` (just the Bech32 address)
   - Calls API: `POST /donate_to/{destination}/{original}/{signature}`

2. The API endpoint format:
   - URL: `/donate_to/{destination_address}/{original_address}/{signature}`
   - Only the original address needs to sign
   - Message is just the destination address in Bech32 format

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

### "HTTP 429 Rate Limited"
- API is rate-limiting requests
- Increase `--delay` in `check_all_allocations.py`
- Wait a few minutes and try again
- Browser API is less likely to be rate-limited

### "Address file not found"
- Generate the JSON file first using `generate_addresses.py`
- Check the file path is correct

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
