# NIGHT Token Consolidation Scripts

These scripts help you consolidate NIGHT tokens from multiple Cardano addresses into a single destination address using the Scavenger Mine API `/donate_to` endpoint.

## Overview

The workflow consists of two scripts:

1. **`generate_addresses.py`** - Generates a JSON file containing addresses derived from your mnemonic
2. **`consolidate_night.py`** - Uses the JSON file to consolidate tokens into a destination address

This separation allows you to:
- Review the addresses before consolidating
- Manually edit the JSON if needed
- Reuse the address list without re-entering your mnemonic
- Keep your mnemonic separate from the address list

## Features

- Derives Cardano addresses from a BIP39 mnemonic phrase
- Consolidates rewards from multiple accounts/addresses into one
- Handles CIP-30 signatures required by the API
- Supports both testnet and mainnet
- Provides clear progress feedback
- JSON-based address list for flexibility

## Installation

1. Install Python 3.8 or higher

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Step 1: Generate Address List

First, generate a JSON file with addresses from your mnemonic:

```bash
python generate_addresses.py \
  --mnemonic "word1 word2 word3 ... word24" \
  --accounts 0 1 2 3 4 \
  -o addresses.json
```

This creates `addresses.json` containing:
- All source addresses to consolidate from
- The destination address
- Network information (testnet/mainnet)
- Account and index information for each address

### Step 2: Consolidate Tokens

Then use the JSON file to consolidate:

```bash
python consolidate_night.py \
  --addresses addresses.json \
  --mnemonic "word1 word2 word3 ... word24"
```

The script will:
- Load addresses from the JSON file
- Derive signing keys from your mnemonic (as needed)
- Consolidate each source address to the destination
- Show progress and results

### Complete Example

```bash
# Generate addresses for accounts 0-4, consolidating to account 0
python generate_addresses.py \
  --mnemonic "your twelve or twenty four word mnemonic phrase here" \
  --accounts 0 1 2 3 4 \
  --destination-account 0 \
  -o my_addresses.json

# Review the generated JSON file (optional)
cat my_addresses.json

# Consolidate all addresses
python consolidate_night.py \
  --addresses my_addresses.json \
  --mnemonic "your twelve or twenty four word mnemonic phrase here"
```

### Advanced Examples

**Generate for mainnet:**
```bash
python generate_addresses.py \
  --mnemonic "word1 ... word24" \
  --accounts 0 1 2 \
  --mainnet \
  -o addresses_mainnet.json
```

**Check more address indices:**
```bash
python generate_addresses.py \
  --mnemonic "word1 ... word24" \
  --accounts 0 1 2 \
  --max-index 20 \
  -o addresses.json
```

**Consolidate to a different account:**
```bash
python generate_addresses.py \
  --mnemonic "word1 ... word24" \
  --accounts 0 1 2 3 \
  --destination-account 5 \
  -o addresses.json
```

## Command Line Arguments

### generate_addresses.py

- `--mnemonic` (required): Your BIP39 mnemonic phrase (12, 15, 18, 21, or 24 words)
- `--accounts` (required): Space-separated list of account numbers to generate addresses for
- `--destination-account` (optional): Account number for destination address (default: 0)
- `--destination-index` (optional): Address index for destination address (default: 0)
- `--max-index` (optional): Maximum address index to generate per account (default: 10)
- `--mainnet` (optional): Use Cardano mainnet instead of testnet
- `-o, --output` (optional): Output JSON file path (default: addresses.json)

### consolidate_night.py

- `--addresses` (required): Path to JSON file containing address list
- `--mnemonic` (required): BIP39 mnemonic phrase (used to derive signing keys)

## JSON File Format

The generated JSON file has the following structure:

```json
{
  "network": "testnet",
  "destination": {
    "address": "addr_test1...",
    "account": 0,
    "index": 0
  },
  "source_addresses": [
    {
      "address": "addr_test1...",
      "account": 0,
      "index": 0
    },
    {
      "address": "addr_test1...",
      "account": 1,
      "index": 0
    }
  ]
}
```

You can manually edit this file if needed (e.g., to remove addresses or add custom ones).

## How It Works

1. **Address Derivation**: Both scripts derive Cardano addresses from your mnemonic using BIP44 derivation paths:
   - Path format: `m/44'/1815'/account'/0/index`
   - 1815 is the Cardano coin type
   - **Note**: Some modern Cardano wallets (like Daedalus, Yoroi) use CIP-1852 instead (`m/1852'/1815'/account'/0/index`). If your addresses don't match, your wallet may be using CIP-1852. In that case, you may need to modify the scripts or use a wallet that supports BIP44 derivation.

2. **Consolidation**: For each source address, the script:
   - Derives the signing key from the mnemonic (using account/index from JSON)
   - Creates a CIP-30 signature over the message: `"Assign accumulated Scavenger rights to: {destination_address}"`
   - Signs with both the source and destination address signing keys
   - Calls the `/donate_to` API endpoint

3. **Error Handling**: The script handles common errors:
   - Address not registered (skips gracefully)
   - Already consolidated (shows message)
   - Other API errors (reports clearly)

## Security Notes

⚠️ **Important**: Both scripts require your mnemonic phrase. Keep it secure:

- Never share your mnemonic with anyone
- Run these scripts on a secure, trusted machine
- Consider using a hardware wallet for better security
- Review the code before running it with your real mnemonic
- The JSON file contains addresses but not private keys (keys are derived on-the-fly from mnemonic)

## API Reference

These scripts use the Scavenger Mine API endpoint:
- **Base URL**: `https://scavenger.prod.gd.midnighttge.io`
- **Endpoint**: `POST /donate_to/{original_address}/{destination_address}/{signature_original}/{signature_destination}`

For more details, see the [Scavenger Mine API documentation](https://45047878.fs1.hubspotusercontent-na1.net/hubfs/45047878/Midnight%20-%20Whitepaper%20treatment%20for%20Scavenger%20Mine%20API%20V3.pdf).

## Troubleshooting

### "Address not registered"
- The address hasn't been registered in the Scavenger Mine system
- This is normal for addresses that haven't participated in mining
- The script will skip these addresses automatically

### "Conflict" error
- The address has already been consolidated to another address
- Each address can only be consolidated once
- The script will skip these addresses automatically

### "Address file not found"
- Make sure you've generated the JSON file first using `generate_addresses.py`
- Check the file path is correct

### Signature errors
- Ensure you're using the correct mnemonic
- Verify the JSON file matches the addresses derived from your mnemonic
- Check that the network (testnet/mainnet) matches

### Addresses don't match your wallet
- Your wallet may be using CIP-1852 instead of BIP44
- You may need to modify the derivation path in the scripts
- Check your wallet's documentation for the derivation path it uses

## License

These scripts are provided as-is for educational and personal use.
