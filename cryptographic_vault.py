import argparse
import getpass
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes



MAGIC = b"CVLT1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 600_000
VAULT_DIR_NAME = ".vault_data"
BACKUP_FILE_NAME = "key_backup.json"
MANIFEST_FILE_NAME = "manifest.json"


def derive_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(source: Path):
    return [
        p for p in source.rglob("*")
        if p.is_file() and p.name not in {BACKUP_FILE_NAME, MANIFEST_FILE_NAME}
    ]


def encrypt_file(path: Path, source_root: Path, output_root: Path, key: bytes):
    relative = path.relative_to(source_root)
    output_path = output_root / (str(relative) + ".enc")
    output_path.parent.mkdir(parents=True, exist_ok=True)

    nonce = os.urandom(NONCE_SIZE)
    plaintext = path.read_bytes()
    aad = str(relative).replace("\\", "/").encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)

    with output_path.open("wb") as f:
        f.write(MAGIC)
        f.write(nonce)
        f.write(ciphertext)

    return {
        "path": str(relative).replace("\\", "/"),
        "size": len(plaintext),
        "sha256": hashlib.sha256(plaintext).hexdigest(),
    }


def decrypt_file(path: Path, output_root: Path, key: bytes, relative_name: str):
    data = path.read_bytes()

    if not data.startswith(MAGIC):
        raise ValueError(f"Invalid vault file: {path}")

    nonce_start = len(MAGIC)
    nonce = data[nonce_start:nonce_start + NONCE_SIZE]
    ciphertext = data[nonce_start + NONCE_SIZE:]

    relative = Path(relative_name)
    output_path = output_root / relative
    output_path.parent.mkdir(parents=True, exist_ok=True)

    aad = relative_name.replace("\\", "/").encode("utf-8")
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, aad)
    output_path.write_bytes(plaintext)


def write_json(path: Path, data: dict):
    path.write_text(json.dumps(data, indent=4), encoding="utf-8")


def encrypt_directory(source: Path, vault: Path, password: str):
    source = source.resolve()
    vault = vault.resolve()

    if not source.is_dir():
        raise ValueError(f"Source directory does not exist: {source}")

    if source == vault:
        raise ValueError("Source and vault directories must be different.")

    vault.mkdir(parents=True, exist_ok=True)

    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)

    files = collect_files(source)
    manifest = {
        "format": 1,
        "algorithm": "AES-256-GCM",
        "kdf": "PBKDF2-HMAC-SHA256",
        "pbkdf2_iterations": PBKDF2_ITERATIONS,
        "files": [],
    }

    print("=" * 58)
    print("        CRYPTOGRAPHIC ENCRYPTION VAULT")
    print("=" * 58)
    print(f"Source Directory : {source}")
    print(f"Files Found      : {len(files)}")
    print()

    temp_dir = Path(tempfile.mkdtemp(prefix="vault_build_", dir=str(vault.parent)))
    try:
        encrypted_root = temp_dir / VAULT_DIR_NAME
        encrypted_root.mkdir()

        for path in files:
            entry = encrypt_file(path, source, encrypted_root, key)
            manifest["files"].append(entry)
            print(f"[+] Encrypted: {entry['path']}")

        write_json(temp_dir / MANIFEST_FILE_NAME, manifest)

        # This is a key-backup of derivation parameters, NOT the plaintext AES key.
        backup = {
            "format": 1,
            "kdf": "PBKDF2-HMAC-SHA256",
            "iterations": PBKDF2_ITERATIONS,
            "salt_hex": salt.hex(),
            "key_size_bytes": KEY_SIZE,
            "note": "This file does not contain the encryption key. Keep it with the vault.",
        }
        write_json(temp_dir / BACKUP_FILE_NAME, backup)

        final_vault = vault
        for item in final_vault.iterdir():
            if item.is_dir():
                shutil.rmtree(item)
            else:
                item.unlink()

        shutil.move(str(temp_dir / VAULT_DIR_NAME), str(final_vault / VAULT_DIR_NAME))
        shutil.move(str(temp_dir / MANIFEST_FILE_NAME), str(final_vault / MANIFEST_FILE_NAME))
        shutil.move(str(temp_dir / BACKUP_FILE_NAME), str(final_vault / BACKUP_FILE_NAME))

        print()
        print("[+] Encryption completed successfully.")
        print("[+] Key backup created.")
        print(f"[+] Vault location: {final_vault}")
        print()
        return len(files)
    finally:
        if temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)


def decrypt_directory(vault: Path, output: Path, password: str):
    vault = vault.resolve()
    output = output.resolve()

    manifest_path = vault / MANIFEST_FILE_NAME
    backup_path = vault / BACKUP_FILE_NAME
    encrypted_root = vault / VAULT_DIR_NAME

    if not manifest_path.is_file() or not backup_path.is_file() or not encrypted_root.is_dir():
        raise ValueError("Invalid vault structure.")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    backup = json.loads(backup_path.read_text(encoding="utf-8"))

    salt = bytes.fromhex(backup["salt_hex"])
    key = derive_key(password, salt)

    if output.exists():
        if any(output.iterdir()):
            raise ValueError("Output directory must be empty.")
    else:
        output.mkdir(parents=True)

    print("=" * 58)
    print("             VAULT DECRYPTION")
    print("=" * 58)
    print(f"Encrypted Files : {len(manifest['files'])}")
    print()

    for entry in manifest["files"]:
        encrypted_path = encrypted_root / (entry["path"] + ".enc")
        if not encrypted_path.is_file():
            raise FileNotFoundError(f"Missing encrypted file: {entry['path']}.enc")

        decrypt_file(encrypted_path, output, key, entry["path"])
        print(f"[+] Decrypted: {entry['path']}")

    print()
    print("[+] Decryption completed successfully.")
    return len(manifest["files"])


def verify_directory(original: Path, restored: Path, manifest_path: Path):
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    print()
    print("[+] File integrity verification")

    for entry in manifest["files"]:
        original_file = original / entry["path"]
        restored_file = restored / entry["path"]

        if not original_file.is_file() or not restored_file.is_file():
            raise AssertionError(f"Missing file during verification: {entry['path']}")

        original_hash = sha256_file(original_file)
        restored_hash = sha256_file(restored_file)

        if original_hash != restored_hash:
            raise AssertionError(f"Hash mismatch: {entry['path']}")

    print("[+] All restored files match originals")
    print("STATUS: SUCCESS")


def main():
    parser = argparse.ArgumentParser(
        description="Secure recursive directory encryption vault using AES-256-GCM."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a directory.")
    enc.add_argument("source", type=Path)
    enc.add_argument("vault", type=Path)

    dec = sub.add_parser("decrypt", help="Decrypt a vault.")
    dec.add_argument("vault", type=Path)
    dec.add_argument("output", type=Path)

    verify = sub.add_parser("verify", help="Verify restored files against originals.")
    verify.add_argument("original", type=Path)
    verify.add_argument("restored", type=Path)
    verify.add_argument("vault", type=Path)

    args = parser.parse_args()

    try:
        if args.command == "encrypt":
            password = getpass.getpass("Enter master passphrase: ")
            confirm = getpass.getpass("Confirm master passphrase: ")
            if password != confirm:
                raise ValueError("Passphrases do not match.")
            encrypt_directory(args.source, args.vault, password)

        elif args.command == "decrypt":
            password = getpass.getpass("Enter master passphrase: ")
            decrypt_directory(args.vault, args.output, password)

        elif args.command == "verify":
            verify_directory(args.original, args.restored, args.vault / MANIFEST_FILE_NAME)

    except Exception as exc:
        print(f"\n[!] ERROR: {exc}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
