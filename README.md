# Passkey Manager for Windows (`passkeys_harding.py`)

A lightweight Python CLI utility designed for Windows to inspect, resolve relying parties for, and safely remove stored WebAuthn / FIDO2 passkeys (hardware keys or platform authenticators) managed by the Windows NGC (Next Generation Cryptography) key storage.

Inspired by [`passwordless/webauthn-fido2-key-remover`](https://github.com/passwordless/webauthn-fido2-key-remover/tree/main).

---

<img src="example.avif" alt="Passkeys Harding" width="100%">

## Features

- **Inspect Passkeys:** Lists all WebAuthn/FIDO2 credentials currently registered on the Windows machine via native `certutil`.
- **Relying Party (RP) Resolution:** Hashes candidate domains (SHA-256) to map raw cryptographic hashes back to human-readable domain names (e.g., `google.com`, `github.com`).
- **Browser History & Login Data Mining:** Automatically searches Chrome, Edge, Brave, and Firefox history/logins to discover relying party domains you have visited.
- **Subdomain Guessing:** Automatically tests common subdomains (`www`, `login`, `accounts`, `id`, `auth`, `app`, `sso`) to maximize domain resolution rate.
- **Custom Domain Lists:** Supports loading external domain lists (e.g., Tranco top 1M) for deep credential mapping.
- **Selective or Bulk Deletion:** Easily remove specific passkeys by ID or bulk delete all entries.

---

## Prerequisites

- **OS:** Windows 10 / 11 (requires `certutil`, which is built into Windows).
- **Python:** Python 3.8 or higher.
- **Dependencies:** `rich` library for formatted terminal output.

To install required Python libraries:

```bash
pip install rich
```

*Note: Administrative privileges are required when deleting keys.*

---

## Usage Examples

### 1. Basic Inspection
Inspect stored passkeys using the built-in domain dictionary:

```bash
python passkeys_harding.py
```

### 2. Auto-Detect Browsers for Unmapped Domains
Scan local browser histories (Chrome, Edge, Brave, Firefox) to resolve unknown relying party hashes:

```bash
python passkeys_harding.py --history
```

### 3. Subdomain Expansion
Expand candidate domains with common prefixes (`www`, `login`, `accounts`, etc.):

```bash
python passkeys_harding.py --guess
```

### 4. Deep Domain Discovery (Recommended for full mapping)
Download a large domain list (like Tranco Top 1M) and combine all discovery methods:

```bash
# Download and extract the top 1M domains
wget https://tranco-list.eu/top-1m.csv.zip
# Format to one domain per line (using ripgrep/grep)
rg -o -r $1 "\d+,(.*)" top-1m.csv > top-1m.txt

# Run full discovery
python passkeys_harding.py --domains top-1m.txt --guess --history
```

### 5. Deleting Keys
To delete specific keys by ID (run terminal as **Administrator**):

```bash
# Delete key ID 1 and ID 3
python passkeys_harding.py --delete 1 3

# Delete all stored FIDO keys
python passkeys_harding.py --delete all
```

---

## Command Line Arguments

| Option | Argument | Description |
| :--- | :--- | :--- |
| `--domains` | `FILE` | Text file with one domain per line to resolve RP hashes. |
| `--guess` | *None* | Tests common prefixes (`www`, `login`, `accounts`, etc.) and root domains. |
| `--history` | `[all\|PATH]` | Reads browser history/saved logins. Auto-detects installed browsers if left blank or set to `all`. Can also point to a specific file or profile folder. |
| `--delete` | `ID [ID ...]` or `all` | Deletes specified key IDs or all keys. **(Requires Admin privileges)** |

---

## How It Works

1. **Key Extraction:** Runs `certutil -csp NGC -key` to retrieve registered FIDO key containers.
2. **Username & Hash Decoding:** Extracts the base-16 encoded username and SHA-256 hash of the Relying Party ID (`rpId`).
3. **Domain Matching:** Computes SHA-256 hashes for known, guessed, or browser-discovered domains and matches them against stored credential hashes.
4. **Key Removal:** Invokes `certutil -csp NGC -delkey <key_name>` for selected key identifiers.

---

## License

This project is licensed under the GPL License.