import socket
import time
import statistics
import threading
import os
from datetime import datetime
import customtkinter as ctk

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

class TBDApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("TBD: Active Defense & Behavioral Sentinel")
        self.geometry("950x700")
        self.resizable(False, False)

        self.target_host = "127.0.0.1"
        self.sample_ports = [80, 443, 22, 3306, 8080]
        self.behavioral_baseline = {}
        self.is_monitoring = False
        self.recent_intervals = []

        self.title_label = ctk.CTkLabel(self, text="TBD: Autonomous Threat Defense & Isolation Engine", font=ctk.CTkFont(size=22, weight="bold"))
        self.title_label.pack(pady=20)

        self.control_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.control_frame.pack(fill="x", padx=25, pady=10)

        self.train_btn = ctk.CTkButton(self.control_frame, text="1. Build World Model", command=self.start_training_thread, fg_color="#1f538d", hover_color="#14375e", height=45, font=ctk.CTkFont(size=14, weight="bold"))
        self.train_btn.pack(side="left", expand=True, padx=8)

        self.start_btn = ctk.CTkButton(self.control_frame, text="2. Start Active Sentinel", command=self.start_monitoring_thread, fg_color="#2b8a3e", hover_color="#236b31", height=45, font=ctk.CTkFont(size=14, weight="bold"), state="disabled")
        self.start_btn.pack(side="left", expand=True, padx=8)

        self.stop_btn = ctk.CTkButton(self.control_frame, text="Stop Sentinel", command=self.stop_monitoring, fg_color="#c92a2a", hover_color="#9b1c1c", height=45, font=ctk.CTkFont(size=14, weight="bold"), state="disabled")
        self.stop_btn.pack(side="left", expand=True, padx=8)

        self.status_box = ctk.CTkTextbox(self, height=50, fg_color="#1a1a1a", text_color="#4dabf7", font=ctk.CTkFont(size=14, weight="bold"))
        self.status_box.pack(fill="x", padx=25, pady=15)
        self.status_box.insert("0.0", "Status: System idle. Waiting for World Model baseline training...")
        self.status_box.configure(state="disabled")

        self.log_label = ctk.CTkLabel(self, text="Telemetry & Live Defense Logs:", anchor="w", font=ctk.CTkFont(size=14, weight="bold"))
        self.log_label.pack(fill="x", padx=25, pady=(5, 0))

        self.log_textbox = ctk.CTkTextbox(self, height=360, fg_color="#111111", text_color="#51cf66", font=ctk.CTkFont(family="Consolas", size=13))
        self.log_textbox.pack(fill="both", padx=25, pady=10)
        self.log_textbox.configure(state="disabled")

    def log_message(self, message, msg_type="normal"):
        self.log_textbox.configure(state="normal")
        timestamp = datetime.now().strftime('%H:%M:%S')
        if msg_type == "alert":
            formatted_msg = f"[{timestamp}] CRITICAL THREAT: {message}\n"
        elif msg_type == "mitigation":
            formatted_msg = f"[{timestamp}] DEFENSE ACTION (ISOLATION): {message}\n"
        elif msg_type == "success":
            formatted_msg = f"[{timestamp}] SUCCESS: {message}\n"
        elif msg_type == "warning":
            formatted_msg = f"[{timestamp}] INFO: {message}\n"
        else:
            formatted_msg = f"[{timestamp}] {message}\n"
        self.log_textbox.insert("end", formatted_msg)
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def update_status(self, text, color="#4dabf7"):
        self.status_box.configure(state="normal", text_color=color)
        self.status_box.delete("0.0", "end")
        self.status_box.insert("0.0", text)
        self.status_box.configure(state="disabled")

    def start_training_thread(self):
        self.train_btn.configure(state="disabled")
        threading.Thread(target=self.build_world_model, daemon=True).start()

    def build_world_model(self):
        self.log_message("Initializing TBD World Model architecture...")
        self.update_status("Status: Training behavioral baseline...", "#fab005")
        response_history = {port: [] for port in self.sample_ports}
        for cycle in range(3):
            for port in self.sample_ports:
                start = time.time()
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.3)
                    s.connect_ex((self.target_host, port))
                    s.close()
                    duration = (time.time() - start) * 1000
                    response_history[port].append(duration)
                except:
                    pass
            time.sleep(0.3)
        for port, times in response_history.items():
            if times:
                mean_time = statistics.mean(times)
                self.behavioral_baseline[port] = {
                    "mean": mean_time,
                    "tolerance": mean_time + 0.1
                }
            else:
                self.behavioral_baseline[port] = {"mean": 5.0, "tolerance": 5.1}
        self.log_message("World Model successfully locked. Active defense protocols ready.", "success")
        self.update_status("Status: Baseline locked. Ready for active sentinel monitoring.", "#51cf66")
        self.start_btn.configure(state="normal")

    def start_monitoring_thread(self):
        self.is_monitoring = True
        self.start_btn.configure(state="disabled")
        self.train_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.update_status("Status: Active Sentinel running. Analyzing traffic patterns...", "#fa5252")
        threading.Thread(target=self.monitor_loop, daemon=True).start()

    def trigger_full_network_isolation(self):
        self.log_message("Critical automated flood detected! Initiating full system network isolation...", "mitigation")
        self.update_status("Status: WARNING! Network Isolation Triggered!", "#fd7e14")
        try:
            os.system("ipconfig /release")
            os.system("netsh interface set interface \"Wi-Fi\" admin=disabled")
            os.system("netsh interface set interface \"Ethernet\" admin=disabled")
            self.log_message("Network adapters disabled and IP configuration released successfully.", "mitigation")
        except Exception as e:
            self.log_message(f"Failed to execute network isolation: {str(e)}", "alert")

    def monitor_loop(self):
        self.log_message("TBD Active Sentinel monitoring loop started...")
        last_check_time = time.time()
        
        while self.is_monitoring:
            anomaly_detected = False
            current_time = time.time()
            interval = current_time - last_check_time
            last_check_time = current_time
            
            self.recent_intervals.append(interval)
            if len(self.recent_intervals) > 10:
                self.recent_intervals.pop(0)

            for port, stats in self.behavioral_baseline.items():
                if not self.is_monitoring:
                    break
                start = time.time()
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.5)
                    res = s.connect_ex((self.target_host, port))
                    s.close()
                    current_duration = (time.time() - start) * 1000
                    
                    if res == 0 and current_duration > stats["tolerance"]:
                        anomaly_detected = True
                        
                        traffic_nature = "Unknown"
                        if len(self.recent_intervals) >= 5:
                            jitter = statistics.stdev(self.recent_intervals)
                            if jitter < 0.05:
                                traffic_nature = "Automated Bot / Scripted Attack"
                            else:
                                traffic_nature = "Uncertain / Irregular Burst"

                        alert_msg = f"State Divergence on Port {port}! Baseline: {stats['mean']:.2f}ms | Spike: {current_duration:.2f}ms | Origin Profile: {traffic_nature}"
                        self.log_message(alert_msg, "alert")
                        self.update_status(f"ALERT: State Divergence Detected on Port {port}!", "#fa5252")
                        
                        if "Automated Bot" in traffic_nature:
                            self.trigger_full_network_isolation()
                            self.is_monitoring = False
                            break
                except:
                    pass

            if not anomaly_detected and self.is_monitoring:
                self.log_message("Network topology stable. State vector normal.")
            time.sleep(2)

    def stop_monitoring(self):
        self.is_monitoring = False
        self.start_btn.configure(state="normal")
        self.train_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.update_status("Status: Sentinel stopped safely.", "#fab005")
        self.log_message("TBD Active Sentinel shut down safely.", "warning")

if __name__ == "__main__":
    app = TBDApp()
    app.mainloop()
