import os
import json
import hashlib
import time
from pathlib import Path

class QuarantineManager:
    """
    Secure Quarantine Vault:
    Isolates malicious files by encrypting their payload with an XOR key,
    scrambling file extensions, and storing metadata for safe recovery or permanent deletion.
    """

    VAULT_DIR = Path.home() / ".tbd_quarantine"
    METADATA_FILE = VAULT_DIR / "quarantine_manifest.json"
    XOR_KEY = 0x5A  # Inversion mask to render PE and scripts non-executable

    @classmethod
    def _ensure_vault(cls):
        cls.VAULT_DIR.mkdir(parents=True, exist_ok=True)
        if not cls.METADATA_FILE.exists():
            with open(cls.METADATA_FILE, "w", encoding="utf-8") as f:
                json.dump({}, f)

    @classmethod
    def _read_manifest(cls) -> dict:
        cls._ensure_vault()
        try:
            with open(cls.METADATA_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    @classmethod
    def _write_manifest(cls, manifest: dict):
        cls._ensure_vault()
        with open(cls.METADATA_FILE, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)

    @classmethod
    def quarantine_file(cls, filepath: str, threat_name: str, detection_source: str = "Behavioral") -> tuple[bool, str]:
        """
        Quarantines a target file:
        1. Reads file bytes and calculates SHA-256.
        2. Obfuscates bytes using XOR mask to neutralize execution.
        3. Saves as .tbdq inside quarantine vault.
        4. Removes original file.
        5. Saves metadata.
        """
        p = Path(filepath)
        if not p.is_file():
            return False, "File does not exist."

        try:
            raw_bytes = p.read_bytes()
            file_hash = hashlib.sha256(raw_bytes).hexdigest()
            file_size = len(raw_bytes)

            # Neutralize payload with XOR masking
            obfuscated_bytes = bytes([b ^ cls.XOR_KEY for b in raw_bytes])
            
            cls._ensure_vault()
            quarantine_filename = f"{file_hash[:16]}.tbdq"
            vault_target = cls.VAULT_DIR / quarantine_filename
            vault_target.write_bytes(obfuscated_bytes)

            # Remove original threat
            p.unlink(missing_ok=True)

            # Record manifest
            manifest = cls._read_manifest()
            manifest[file_hash] = {
                "id": file_hash[:16],
                "original_path": str(p.resolve()),
                "filename": p.name,
                "threat_name": threat_name,
                "detection_source": detection_source,
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "file_size": file_size,
                "vault_file": str(vault_target.resolve())
            }
            cls._write_manifest(manifest)

            return True, f"Threat successfully quarantined: {p.name}"
        except Exception as e:
            return False, f"Failed to quarantine file: {str(e)}"

    @classmethod
    def restore_file(cls, threat_id: str) -> tuple[bool, str]:
        """Restores a quarantined file back to its original location."""
        manifest = cls._read_manifest()
        target_hash = None
        for h, item in manifest.items():
            if item.get("id") == threat_id or h == threat_id:
                target_hash = h
                break

        if not target_hash:
            return False, "Threat ID not found in vault."

        item = manifest[target_hash]
        vault_path = Path(item["vault_file"])
        orig_path = Path(item["original_path"])

        if not vault_path.exists():
            return False, "Quarantine storage file missing."

        try:
            # Reconstruct original bytes (XOR is symmetric)
            obfuscated = vault_path.read_bytes()
            original_bytes = bytes([b ^ cls.XOR_KEY for b in obfuscated])
            
            orig_path.parent.mkdir(parents=True, exist_ok=True)
            orig_path.write_bytes(original_bytes)
            
            # Remove from vault and manifest
            vault_path.unlink(missing_ok=True)
            del manifest[target_hash]
            cls._write_manifest(manifest)

            return True, f"File successfully restored to: {str(orig_path)}"
        except Exception as e:
            return False, f"Restoration error: {str(e)}"

    @classmethod
    def delete_quarantined_file(cls, threat_id: str) -> tuple[bool, str]:
        """Permanently purges a quarantined file from storage."""
        manifest = cls._read_manifest()
        target_hash = None
        for h, item in manifest.items():
            if item.get("id") == threat_id or h == threat_id:
                target_hash = h
                break

        if not target_hash:
            return False, "Threat ID not found."

        item = manifest[target_hash]
        vault_path = Path(item["vault_file"])
        vault_path.unlink(missing_ok=True)
        del manifest[target_hash]
        cls._write_manifest(manifest)
        return True, "File permanently deleted from quarantine vault."

    @classmethod
    def get_all_quarantined(cls) -> list:
        manifest = cls._read_manifest()
        return list(manifest.values())
