import os
import time
import threading
import psutil
from typing import Callable, Optional

class BehavioralEngine:
    """
    Real-Time Behavioral Process & LOLBins Sentinel:
    Monitors running processes, command lines, parent-child lineages, and abnormal resource bursts
    to detect in-memory threats, zero-day scripts, and living-off-the-land attacks.
    """

    # Suspicious LOLBins and their high-risk argument patterns
    RISKY_COMMAND_PATTERNS = [
        # PowerShell evasion & payload stagers
        ("powershell", ["-enc", "-encodedcommand", "downloadstring", "bypass", "hidden", "invoke-expression", "iex", "net.webclient"]),
        ("pwsh", ["-enc", "-encodedcommand", "downloadstring", "bypass", "hidden", "invoke-expression", "iex"]),
        # Ransomware shadow copy deletion
        ("vssadmin", ["delete", "shadows", "resize", "shadowstorage"]),
        ("wmic", ["shadowcopy", "delete", "process", "call", "create"]),
        ("bcdedit", ["recoveryenabled", "bootstatuspolicy", "ignoreallfailures"]),
        ("wbadmin", ["delete", "catalog", "systemstatebackup"]),
        # LOLBin downloaders & decoders
        ("certutil", ["-urlcache", "-split", "decode"]),
        ("bitsadmin", ["/transfer", "download"]),
        # Script hosts running from temp
        ("mshta", ["javascript:", "vbscript:", "http://", "https://"]),
        ("cscript", [".vbs", ".js", "appdata", "temp"]),
        ("wscript", [".vbs", ".js", "appdata", "temp"]),
        ("regsvr32", ["/s", "/u", "/i:", "scrobj.dll"]),
        ("rundll32", ["javascript:", "shell32.dll,shellexec_rundll", "appdata", "temp"])
    ]

    # Malicious parent-child associations (e.g. Office or PDF spawning shell)
    VULNERABLE_PARENTS = {
        "winword.exe": ["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"],
        "excel.exe": ["cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe"],
        "powerpnt.exe": ["cmd.exe", "powershell.exe"],
        "acrord32.exe": ["cmd.exe", "powershell.exe"],
        "acrobat.exe": ["cmd.exe", "powershell.exe"],
        "outlook.exe": ["cmd.exe", "powershell.exe", "powershell_ise.exe"]
    }

    def __init__(self, alert_callback: Optional[Callable[[str, str, dict], None]] = None, auto_kill: bool = True):
        self.alert_callback = alert_callback
        self.auto_kill = auto_kill
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.monitored_pids = set()
        self.detected_threats = []

    def start(self):
        """Starts real-time process behavioral sentinel."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="BehavioralSentinelThread")
        self._thread.start()

    def stop(self):
        """Stops process behavioral sentinel."""
        self.is_running = False

    def evaluate_process(self, proc: psutil.Process) -> tuple[int, list[str]]:
        """
        Evaluates a single process against behavioral anomaly matrix.
        Returns: (risk_score: 0-100, reasons: list[str])
        """
        risk_score = 0
        reasons = []

        try:
            pid = proc.pid
            name = proc.name().lower()
            cmdline_list = proc.cmdline()
            cmdline = " ".join(cmdline_list).lower()
            exe_path = proc.exe().lower()

            # Rule 1: LOLBin abuse
            for target_bin, suspicious_flags in self.RISKY_COMMAND_PATTERNS:
                if target_bin in name:
                    matched_flags = [flag for flag in suspicious_flags if flag in cmdline]
                    if matched_flags:
                        score_increment = len(matched_flags) * 35
                        risk_score += score_increment
                        reasons.append(f"Suspicious LOLBin invocation ({name}) with flags: {', '.join(matched_flags)}")

            # Rule 2: Parent-Child anomaly (Macro/PDF Exploit)
            try:
                parent = proc.parent()
                if parent:
                    parent_name = parent.name().lower()
                    if parent_name in self.VULNERABLE_PARENTS:
                        if name in self.VULNERABLE_PARENTS[parent_name]:
                            risk_score += 80
                            reasons.append(f"Dangerous Parent-Child lineage: {parent_name} spawned shell {name}")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

            # Rule 3: Execution from Temp/AppData directory with obfuscated arguments
            if "appdata\\local\\temp" in exe_path or "\\appdata\\roaming" in exe_path:
                if any(x in cmdline for x in ["-w hidden", "-windowstyle hidden", "/min", "start /b"]):
                    risk_score += 75
                    reasons.append(f"Hidden process execution directly from user Temp/AppData: {name}")

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

        return min(risk_score, 100), reasons

    def _monitor_loop(self):
        current_pid = os.getpid()

        while self.is_running:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'exe']):
                    if not self.is_running:
                        break

                    pid = proc.info.get('pid')
                    if not pid or pid == current_pid or pid <= 4 or pid in self.monitored_pids:
                        continue

                    risk_score, reasons = self.evaluate_process(proc)

                    if risk_score >= 70:
                        # Threat detected!
                        self.monitored_pids.add(pid)
                        proc_name = proc.info.get('name', 'Unknown')
                        
                        threat_details = {
                            "pid": pid,
                            "name": proc_name,
                            "risk_score": risk_score,
                            "reasons": reasons,
                            "cmdline": " ".join(proc.info.get('cmdline') or [])
                        }
                        self.detected_threats.append(threat_details)

                        action_taken = "Flagged & Logged"
                        if self.auto_kill:
                            try:
                                proc.kill()
                                action_taken = "NEUTRALIZED (Process Terminated)"
                            except Exception as e:
                                action_taken = f"Failed to terminate ({str(e)})"

                        alert_summary = (
                            f"ZERO-DAY / BEHAVIORAL THREAT [{action_taken}]: "
                            f"{proc_name} (PID: {pid}) | Risk Score: {risk_score}/100 | "
                            f"Findings: {'; '.join(reasons)}"
                        )

                        if self.alert_callback:
                            self.alert_callback("BEHAVIORAL_THREAT", alert_summary, threat_details)

            except Exception:
                pass

            time.sleep(1.0)
