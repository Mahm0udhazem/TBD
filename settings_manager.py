import os
import sys
import json
import winreg
from pathlib import Path

class SettingsManager:
    """
    Manages TBD configuration persistence and Windows startup integration.
    Settings file is stored in %APPDATA%/TBD/settings.json.
    """

    CONFIG_DIR = Path(os.environ.get("APPDATA", Path.home())) / "TBD"
    CONFIG_FILE = CONFIG_DIR / "settings.json"
    REG_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "TBD"

    DEFAULT_SETTINGS = {
        "language": "en",               # "en" or "ar"
        "theme": "Dark",                 # "Dark", "Light", "System"
        "auto_start": True,             # Start on Windows boot
        "auto_kill": True,              # Automatically terminate threats
        "sensitivity": "Normal",         # "Normal", "High", "Strict"
        "minimize_to_tray": False,       # Minimize on close
        "canary_locations": {
            "desktop": True,
            "documents": True,
            "downloads": True,
            "pictures": True
        }
    }

    def __init__(self):
        self.settings = self.load_settings()

    def load_settings(self) -> dict:
        """Loads settings from disk, applying defaults for any missing keys."""
        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if self.CONFIG_FILE.exists():
                with open(self.CONFIG_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    merged = dict(self.DEFAULT_SETTINGS)
                    merged.update(data)
                    return merged
        except Exception:
            pass
        return dict(self.DEFAULT_SETTINGS)

    def save_settings(self, new_settings: dict = None) -> bool:
        """Persists settings to disk and syncs Windows auto-start registry entry."""
        if new_settings is not None:
            self.settings.update(new_settings)

        try:
            self.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            with open(self.CONFIG_FILE, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=4, ensure_ascii=False)

            # Sync Windows Run on Startup
            self._sync_auto_start(self.settings.get("auto_start", False))
            return True
        except Exception:
            return False

    def _sync_auto_start(self, enable: bool):
        """Adds or removes the TBD startup entry in the Windows Registry."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_RUN_KEY, 0, winreg.KEY_SET_VALUE) as key:
                if enable:
                    # Determine target executable path
                    if getattr(sys, 'frozen', False):
                        exe_path = f'"{sys.executable}"'
                    else:
                        main_py = Path(__file__).resolve().parent.parent / "TBD.py"
                        exe_path = f'"{sys.executable}" "{str(main_py)}"'

                    winreg.SetValueEx(key, self.APP_NAME, 0, winreg.REG_SZ, exe_path)
                else:
                    try:
                        winreg.DeleteValue(key, self.APP_NAME)
                    except FileNotFoundError:
                        pass
        except Exception:
            pass

    def is_registry_autostart_active(self) -> bool:
        """Verifies if the registry entry actually exists."""
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.REG_RUN_KEY, 0, winreg.KEY_READ) as key:
                val, _ = winreg.QueryValueEx(key, self.APP_NAME)
                return bool(val)
        except Exception:
            return False

    def reset_to_defaults(self) -> dict:
        """Resets all settings back to default values."""
        self.settings = dict(self.DEFAULT_SETTINGS)
        self.save_settings()
        return self.settings
