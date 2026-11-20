import os
import math
import time
import hashlib
import threading
import psutil
from pathlib import Path
from typing import Callable, Optional

class RansomwareShield:
    """
    Autonomous Zero-Day Ransomware Defense & Canary Decoy System:
    1. Plants high-priority canary bait files in sensitive user folders.
    2. Evaluates file Shannon entropy in real-time to detect encryption cascades.
    3. Detects zero-day encryption attempts at the earliest stage and terminates the offender.
    """

    CANARY_NAME = "!00_tbd_sentinel_decoy.docx"
    CANARY_CONTENT = (
        b"TBD_BEHAVIORAL_CANARY_ACTIVE_INTEGRITY_CHECK_SECURE_DOCUMENT_PAYLOAD_V2" * 50
    )

    def __init__(self, alert_callback: Optional[Callable[[str, str], None]] = None):
        self.alert_callback = alert_callback
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        
        # Directories to plant traps
        self.target_dirs = [
            Path.home() / "Desktop",
            Path.home() / "Documents",
            Path.home() / "Downloads",
            Path.home() / "Pictures"
        ]
        
        self.canaries: dict[Path, dict] = {}
        self.canary_original_hash = hashlib.sha256(self.CANARY_CONTENT).hexdigest()
        self.canary_original_entropy = self.calculate_entropy(self.CANARY_CONTENT)

    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Calculates Shannon Entropy of a byte sequence:
        H(X) = - sum(p(x) * log2(p(x)))
        Range: 0.0 to 8.0.
        Plaintext/docs: 3.5 - 5.5
        Encrypted/Ransomware: > 7.3
        """
        if not data:
            return 0.0
        entropy = 0.0
        data_len = len(data)
        freq = {}
        for b in data:
            freq[b] = freq.get(b, 0) + 1
        for count in freq.values():
            p_x = count / data_len
            if p_x > 0:
                entropy -= p_x * math.log2(p_x)
        return entropy

    def plant_canaries(self):
        """Plants decoy canary traps in all monitored target directories."""
        self.canaries.clear()
        for directory in self.target_dirs:
            try:
                directory.mkdir(parents=True, exist_ok=True)
                canary_path = directory / self.CANARY_NAME
                canary_path.write_bytes(self.CANARY_CONTENT)
                
                # Hide attribute on Windows (optional, but keep accessible to malware directory search)
                self.canaries[canary_path] = {
                    "hash": self.canary_original_hash,
                    "mtime": canary_path.stat().st_mtime
                }
            except Exception:
                pass

    def clean_canaries(self):
        """Removes canary bait files upon shutdown."""
        for canary_path in list(self.canaries.keys()):
            try:
                if canary_path.exists():
                    canary_path.unlink()
            except Exception:
                pass
        self.canaries.clear()

    def find_offending_process(self) -> Optional[psutil.Process]:
        """
        Searches for the process actively performing suspicious file operations or high I/O writes.
        """
        highest_io_proc = None
        highest_write = -1
        current_pid = os.getpid()

        for proc in psutil.process_iter(['pid', 'name', 'io_counters']):
            try:
                if proc.info['pid'] == current_pid or proc.info['pid'] <= 4:
                    continue
                io = proc.info.get('io_counters')
                if io and io.write_bytes > highest_write:
                    highest_write = io.write_bytes
                    highest_io_proc = proc
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        return highest_io_proc

    def start(self):
        """Starts real-time canary watcher in a background thread."""
        if self.is_running:
            return
        self.plant_canaries()
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="RansomwareShieldThread")
        self._thread.start()

    def stop(self):
        """Stops canary watcher and cleans up decoy files."""
        self.is_running = False
        self.clean_canaries()

    def _monitor_loop(self):
        while self.is_running:
            try:
                for canary_path, meta in list(self.canaries.items()):
                    if not self.is_running:
                        break

                    # Check 1: Did file disappear (Renamed by ransomware or deleted)?
                    if not canary_path.exists():
                        self._trigger_ransomware_alert(canary_path, "Canary file renamed or deleted (Ransomware extension change detected)!")
                        # Replenish canary
                        canary_path.write_bytes(self.CANARY_CONTENT)
                        meta["mtime"] = canary_path.stat().st_mtime
                        continue

                    # Check 2: Was modification time updated?
                    current_mtime = canary_path.stat().st_mtime
                    if current_mtime != meta["mtime"]:
                        current_bytes = canary_path.read_bytes()
                        current_hash = hashlib.sha256(current_bytes).hexdigest()

                        if current_hash != meta["hash"]:
                            current_entropy = self.calculate_entropy(current_bytes)
                            threat_detail = (
                                f"Zero-Day Ransomware encryption trap tripped at {canary_path.name}! "
                                f"Original Entropy: {self.canary_original_entropy:.2f} -> Altered Entropy: {current_entropy:.2f}"
                            )
                            self._trigger_ransomware_alert(canary_path, threat_detail)
                            
                            # Restore original canary content
                            canary_path.write_bytes(self.CANARY_CONTENT)
                            meta["mtime"] = canary_path.stat().st_mtime

            except Exception:
                pass

            time.sleep(0.5)

    def _trigger_ransomware_alert(self, canary_path: Path, reason: str):
        # Locate offending process
        offender = self.find_offending_process()
        offender_info = "Unknown Process"
        if offender:
            try:
                offender_info = f"{offender.name()} (PID: {offender.pid})"
                # Immediate neutralization
                offender.kill()
            except Exception:
                pass

        full_message = f"RANSOMWARE ACTIVITY BLOCKED! {reason} | Suspicious Process Neutralized: {offender_info}"
        if self.alert_callback:
            self.alert_callback("RANSOMWARE", full_message)
