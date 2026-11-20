import os
import time
import threading
import winreg
from pathlib import Path
from typing import Callable, Optional

class PersistenceGuard:
    """
    Registry & Startup Persistence Guard:
    Monitors Windows auto-start locations (Run keys, Startup folder)
    to detect unauthorized persistence mechanisms installed by malware.
    """

    REG_LOCATIONS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run")
    ]

    def __init__(self, alert_callback: Optional[Callable[[str, str, dict], None]] = None):
        self.alert_callback = alert_callback
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.known_registry_entries = set()
        self.known_startup_files = set()

        # Startup folder path
        self.startup_folder = Path(os.environ.get("APPDATA", "")) / r"Microsoft\Windows\Start Menu\Programs\Startup"

    def _get_registry_entries(self) -> set:
        entries = set()
        for root, subkey in self.REG_LOCATIONS:
            try:
                with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ) as key:
                    count = winreg.QueryInfoKey(key)[1]
                    for i in range(count):
                        name, val, _ = winreg.EnumValue(key, i)
                        entries.add((subkey, name, str(val)))
            except Exception:
                pass
        return entries

    def _get_startup_files(self) -> set:
        files = set()
        try:
            if self.startup_folder.exists():
                for f in self.startup_folder.iterdir():
                    if f.is_file():
                        files.add(f.name)
        except Exception:
            pass
        return files

    def take_baseline(self):
        """Records initial authorized startup entries."""
        self.known_registry_entries = self._get_registry_entries()
        self.known_startup_files = self._get_startup_files()

    def start(self):
        """Starts real-time persistence watchdog."""
        if self.is_running:
            return
        self.take_baseline()
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="PersistenceGuardThread")
        self._thread.start()

    def stop(self):
        """Stops persistence watchdog."""
        self.is_running = False

    def _monitor_loop(self):
        while self.is_running:
            try:
                # 1. Check Registry Run keys
                current_reg = self._get_registry_entries()
                new_reg = current_reg - self.known_registry_entries
                for subkey, name, val in new_reg:
                    self.known_registry_entries.add((subkey, name, val))
                    info = {"location": subkey, "entry_name": name, "command": val}
                    alert_msg = f"UNAUTHORIZED PERSISTENCE INJECTED: Registry Run Key '{name}' -> '{val}'"
                    if self.alert_callback:
                        self.alert_callback("PERSISTENCE_ALERT", alert_msg, info)

                # 2. Check Startup folder
                current_files = self._get_startup_files()
                new_files = current_files - self.known_startup_files
                for filename in new_files:
                    self.known_startup_files.add(filename)
                    info = {"location": "Startup Folder", "filename": filename}
                    alert_msg = f"NEW STARTUP DROPPER DETECTED: File '{filename}' dropped into Startup directory!"
                    if self.alert_callback:
                        self.alert_callback("PERSISTENCE_ALERT", alert_msg, info)

            except Exception:
                pass

            time.sleep(2.0)
