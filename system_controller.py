import os
import sys
import ctypes
import subprocess
import psutil
import re

class SystemController:
    """
    Manages low-level operating system controls:
    - Privilege verification (Admin check)
    - Full system network isolation (Air-gap kill switch)
    - Network restoration (Recovery mechanism)
    - System health and performance telemetry
    """

    @staticmethod
    def is_admin() -> bool:
        """Checks if current process has elevated Administrator privileges."""
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def get_network_adapters():
        """Returns a list of connected network adapter names."""
        adapters = []
        try:
            # Query netsh for interfaces
            output = subprocess.check_output(
                ["netsh", "interface", "show", "interface"],
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            for line in output.splitlines():
                if "Enabled" in line or "Connected" in line or "Disabled" in line or "Disconnected" in line:
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) >= 4:
                        adapters.append(parts[3])
        except Exception:
            # Fallback to standard names
            adapters = ["Wi-Fi", "Ethernet"]
        return adapters

    @classmethod
    def isolate_network(cls) -> tuple[bool, str]:
        """
        Executes immediate host-level network isolation:
        - Releases DHCP lease
        - Disables all active network adapters
        """
        if not cls.is_admin():
            return False, "Administrator privileges required to execute network isolation."

        actions_taken = []
        try:
            # 1. Release IP configuration
            subprocess.run(["ipconfig", "/release"], capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            actions_taken.append("IP configuration released")

            # 2. Disable network adapters
            adapters = cls.get_network_adapters()
            disabled_count = 0
            for adapter in adapters:
                cmd = ["netsh", "interface", "set", "interface", f"name={adapter}", "admin=disabled"]
                res = subprocess.run(cmd, capture_output=True, text=True,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                if res.returncode == 0:
                    disabled_count += 1
            actions_taken.append(f"Disabled {disabled_count} network adapter(s)")

            return True, " | ".join(actions_taken)
        except Exception as e:
            return False, f"Isolation error: {str(e)}"

    @classmethod
    def restore_network(cls) -> tuple[bool, str]:
        """
        Restores host network connectivity after incident mitigation:
        - Re-enables network adapters
        - Renews DHCP lease
        """
        if not cls.is_admin():
            return False, "Administrator privileges required to restore network."

        actions_taken = []
        try:
            # 1. Enable network adapters
            adapters = cls.get_network_adapters()
            enabled_count = 0
            for adapter in adapters:
                cmd = ["netsh", "interface", "set", "interface", f"name={adapter}", "admin=enabled"]
                res = subprocess.run(cmd, capture_output=True, text=True,
                                     creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
                if res.returncode == 0:
                    enabled_count += 1
            actions_taken.append(f"Re-enabled {enabled_count} network adapter(s)")

            # 2. Renew IP configuration
            subprocess.run(["ipconfig", "/renew"], capture_output=True, text=True,
                           creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0)
            actions_taken.append("IP configuration renewed")

            return True, " | ".join(actions_taken)
        except Exception as e:
            return False, f"Restoration error: {str(e)}"

    @staticmethod
    def get_system_telemetry() -> dict:
        """Returns CPU, RAM, and disk utilization metrics."""
        try:
            return {
                "cpu_percent": psutil.cpu_percent(interval=None),
                "ram_percent": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage("C:\\" if os.name == 'nt' else "/").percent,
                "total_processes": len(psutil.pids())
            }
        except Exception:
            return {
                "cpu_percent": 0.0,
                "ram_percent": 0.0,
                "disk_usage": 0.0,
                "total_processes": 0
            }
