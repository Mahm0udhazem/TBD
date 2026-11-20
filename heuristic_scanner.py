import os
import math
import hashlib
import pefile
from pathlib import Path
from typing import Optional

class HeuristicScanner:
    """
    Deep Heuristic & PE Static Analyzer:
    Analyzes Portable Executables (PE), scripts, and documents without running them.
    Evaluates section entropy, import tables, suspicious API clusters, and embedded strings.
    """

    SUSPICIOUS_APIS = {
        "Injection": ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC", "SetThreadContext"],
        "Surveillance": ["SetWindowsHookExA", "SetWindowsHookExW", "GetAsyncKeyState", "GetKeyState"],
        "Evasion": ["IsDebuggerPresent", "CheckRemoteDebuggerPresent", "OutputDebugStringA"],
        "RansomwareCrypto": ["CryptEncrypt", "CryptGenKey", "BCryptEncrypt", "CryptAcquireContextA", "CryptAcquireContextW"]
    }

    RANSOM_STRINGS = [
        b"your personal files are encrypted",
        b"all your files have been encrypted",
        b"decrypt your files",
        b"readme_decrypt",
        b"tor browser",
        b"bitcoin",
        b".onion"
    ]

    SCRIPT_FLAGS = [
        b"-w hidden",
        b"-windowstyle hidden",
        b"downloadstring",
        b"invoke-expression",
        b"iex",
        b"wscript.shell",
        b"cmd.exe /c",
        b"certutil -urlcache"
    ]

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """Calculates Shannon Entropy (0.0 to 8.0)."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @classmethod
    def scan_file(cls, filepath: str) -> dict:
        """
        Performs static heuristic analysis on a target file.
        Returns a rich telemetry dictionary.
        """
        p = Path(filepath)
        if not p.is_file():
            return {"error": "Target file does not exist or is not accessible."}

        try:
            raw_bytes = p.read_bytes()
        except Exception as e:
            return {"error": f"Failed to read file: {str(e)}"}

        file_size = len(raw_bytes)
        file_sha256 = hashlib.sha256(raw_bytes).hexdigest()
        file_md5 = hashlib.md5(raw_bytes).hexdigest()
        overall_entropy = cls.calculate_entropy(raw_bytes)

        risk_score = 0
        findings = []
        is_pe = False
        pe_sections = []
        matched_apis = []

        # 1. Check if Portable Executable (PE: EXE, DLL, SYS)
        if raw_bytes[:2] == b"MZ":
            try:
                pe = pefile.PE(data=raw_bytes)
                is_pe = True

                # Inspect Sections & Entropy
                for section in pe.sections:
                    sec_name = section.Name.decode('latin-1', errors='ignore').strip('\x00')
                    sec_entropy = section.get_entropy()
                    pe_sections.append({
                        "name": sec_name,
                        "entropy": round(sec_entropy, 2),
                        "size": section.SizeOfRawData
                    })

                    # High Section Entropy -> Crypter or Packer
                    if sec_entropy > 7.2:
                        risk_score += 35
                        findings.append(f"High entropy section '{sec_name}' ({sec_entropy:.2f}/8.0) indicating packing/encryption.")

                    # Known packer names
                    if any(packer in sec_name.lower() for packer in ["upx", "aspack", "mpress", "themida", "vmp"]):
                        risk_score += 25
                        findings.append(f"Recognized packer section identified: {sec_name}")

                # Inspect Import Table for Suspicious APIs
                if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                    for entry in pe.DIRECTORY_ENTRY_IMPORT:
                        for imp in entry.imports:
                            if imp.name:
                                api_name = imp.name.decode('latin-1', errors='ignore')
                                for category, apis in cls.SUSPICIOUS_APIS.items():
                                    if api_name in apis:
                                        matched_apis.append(f"{api_name} [{category}]")
                                        risk_score += 15

                pe.close()
            except Exception:
                pass

        # 2. String & Pattern Heuristics
        lower_bytes = raw_bytes.lower()
        for r_str in cls.RANSOM_STRINGS:
            if r_str in lower_bytes:
                risk_score += 50
                findings.append(f"Ransomware signature phrase detected: '{r_str.decode('latin-1')}'")

        for s_flag in cls.SCRIPT_FLAGS:
            if s_flag in lower_bytes:
                risk_score += 25
                findings.append(f"Malicious script invocation pattern: '{s_flag.decode('latin-1')}'")

        # 3. Overall Entropy heuristic if non-PE or packed
        if overall_entropy > 7.4 and not is_pe:
            # High entropy standalone file
            findings.append(f"High overall Shannon entropy: {overall_entropy:.2f}/8.0")

        risk_score = min(risk_score, 100)

        if risk_score >= 60:
            verdict = "MALICIOUS"
        elif risk_score >= 30:
            verdict = "SUSPICIOUS"
        else:
            verdict = "CLEAN"

        return {
            "filename": p.name,
            "filepath": str(p.resolve()),
            "filesize_bytes": file_size,
            "sha256": file_sha256,
            "md5": file_md5,
            "overall_entropy": round(overall_entropy, 2),
            "is_pe": is_pe,
            "pe_sections": pe_sections,
            "matched_apis": matched_apis,
            "risk_score": risk_score,
            "verdict": verdict,
            "findings": findings
        }
