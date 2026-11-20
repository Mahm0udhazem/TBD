import time
import threading
import psutil
from typing import Callable, Optional

class NetworkSentinel:
    """
    Real-Time Outbound Connection & C2 Reverse Shell Watchdog:
    Inspects TCP/UDP connections for suspicious external destinations,
    known backdoor ports, and illegal socket ownership by script hosts.
    """

    KNOWN_BACKDOOR_PORTS = {4444, 1337, 5555, 6667, 8888, 9999, 31337, 4445}
    SUSPICIOUS_NET_PROCESSES = {
        "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe",
        "cscript.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe"
    }

    def __init__(self, alert_callback: Optional[Callable[[str, str, dict], None]] = None, auto_terminate: bool = True):
        self.alert_callback = alert_callback
        self.auto_terminate = auto_terminate
        self.is_running = False
        self._thread: Optional[threading.Thread] = None
        self.flagged_conns = set()

    def start(self):
        """Starts real-time network connection monitoring."""
        if self.is_running:
            return
        self.is_running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="NetworkSentinelThread")
        self._thread.start()

    def stop(self):
        """Stops network connection monitoring."""
        self.is_running = False

    def _monitor_loop(self):
        while self.is_running:
            try:
                conns = psutil.net_connections(kind='inet')
                for c in conns:
                    if not self.is_running:
                        break

                    # Only inspect established or syn_sent outgoing connections
                    if c.status not in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
                        continue

                    raddr = c.raddr
                    if not raddr:
                        continue

                    r_ip, r_port = raddr.ip, raddr.port
                    # Ignore loopback connections
                    if r_ip.startswith("127.") or r_ip == "::1":
                        continue

                    pid = c.pid
                    if not pid or pid <= 4:
                        continue

                    conn_key = (pid, r_ip, r_port)
                    if conn_key in self.flagged_conns:
                        continue

                    try:
                        proc = psutil.Process(pid)
                        proc_name = proc.name().lower()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue

                    is_threat = False
                    reason = ""

                    # Check 1: Known Reverse Shell Port
                    if r_port in self.KNOWN_BACKDOOR_PORTS:
                        is_threat = True
                        reason = f"Connection to known backdoor/C2 port ({r_port})"

                    # Check 2: Script Host or Shell opening non-standard outbound connection
                    elif proc_name in self.SUSPICIOUS_NET_PROCESSES and r_port not in (80, 443):
                        is_threat = True
                        reason = f"Script host ({proc_name}) established external connection to {r_ip}:{r_port}"

                    if is_threat:
                        self.flagged_conns.add(conn_key)
                        threat_info = {
                            "pid": pid,
                            "process_name": proc_name,
                            "remote_ip": r_ip,
                            "remote_port": r_port,
                            "reason": reason
                        }

                        action = "Logged"
                        if self.auto_terminate:
                            try:
                                proc.kill()
                                action = "TERMINATED"
                            except Exception:
                                action = "Termination Failed"

                        alert_msg = (
                            f"NETWORK C2 THREAT [{action}]: Process {proc_name} (PID: {pid}) "
                            f"-> {r_ip}:{r_port} | {reason}"
                        )

                        if self.alert_callback:
                            self.alert_callback("NETWORK_THREAT", alert_msg, threat_info)

            except (psutil.AccessDenied, Exception):
                pass

            time.sleep(1.0)
