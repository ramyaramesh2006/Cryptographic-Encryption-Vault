# Cryptographic Encryption Vault

A Python cybersecurity project that securely encrypts and decrypts complete directory trees using AES-256-GCM and a password-derived key.

## Features

- Recursive directory scanning
- AES-256-GCM authenticated encryption
- PBKDF2-HMAC-SHA256 password-based key derivation
- Random salt and nonce generation
- Secure derivation-parameter backup
- Directory structure preservation
- SHA-256 integrity verification
- Wrong-password protection
- Automated unit tests
- No hard-coded master password

## Security Design

```text
Master Passphrase
       |
       v
PBKDF2-HMAC-SHA256
600,000 iterations + random salt
       |
       v
256-bit AES key
       |
       v
AES-256-GCM
(random 96-bit nonce per file)
       |
       v
Encrypted vault
```

The `key_backup.json` file stores the salt and KDF parameters required to derive the key again. It does **not** store the plaintext AES key or the master passphrase.

## Requirements

- Python 3.10+
- `cryptography`

## Installation

Open PowerShell in the project directory:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell activation is restricted, use:

```powershell
python -m pip install -r requirements.txt
```

## Encrypt a directory

Example:

```powershell
python cryptographic_vault.py encrypt sample_data vault
```

You will be asked for the master passphrase twice.

## Decrypt a vault

Use an empty/non-existing output directory:

```powershell
python cryptographic_vault.py decrypt vault restored_data
```

## Verify restoration

```powershell
python cryptographic_vault.py verify sample_data restored_data vault
```

Successful verification ends with:

```text
[+] All restored files match originals
STATUS: SUCCESS
```

## Run automated tests

```powershell
python -m unittest discover -s tests -v
```

Expected result:

```text
Ran 2 tests
OK
```

## Recommended execution proof screenshots

Take screenshots showing:

1. Installation completed.
2. Encryption command and successful encryption of all sample files.
3. Decryption command and successful restoration.
4. Verification showing `STATUS: SUCCESS`.
5. Unit tests showing `Ran 2 tests` and `OK`.

## Important GitHub safety rules

Never commit:

- A real master password
- Private keys
- Real confidential files
- A real production vault
- Personal credentials
- Sensitive backup material

The included `.gitignore` excludes generated vault contents and Python cache files.

## Project Deliverables

- `cryptographic_vault.py` — main vault application
- `tests/test_vault.py` — automated tests
- `requirements.txt` — dependency list
- `README.md` — setup, usage, and proof instructions
- `sample_data/` — safe demonstration files
- `vault/` — empty directory for generated encrypted vault data

## Disclaimer

This project is intended for authorized defensive/security learning and protecting files you own or are authorized to protect.
