import sys
import os
import threading
import customtkinter as ctk

# Make sure the rest of your project is accessible
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from recon.recon_main import run_recon
from vulnscan.scan_main import run_vuln_scan
from exploit.exploit_main import run_exploit
from privesc.priv_esc import run_priv_esc
from ai_core.classifier import init_model, classify_vulnerabilities

# Theme setup
ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
ctk.set_default_color_theme("blue")  # Optional: "blue", "green", "dark-blue"

class PentestApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("🛡️ Automated Pentesting Tool")
        self.geometry("600x500")
        self.resizable(False, False)

        self.grid_columnconfigure((0, 1), weight=1)
        self.grid_rowconfigure(3, weight=1)

        # Target Input
        self.label = ctk.CTkLabel(self, text="🎯 Enter Target IP or Domain", font=("Arial", 16))
        self.label.grid(row=0, column=0, columnspan=2, pady=(20, 10))

        self.target_entry = ctk.CTkEntry(self, width=400, placeholder_text="e.g. 192.168.56.101 or metasploitable.local")
        self.target_entry.grid(row=1, column=0, columnspan=2, pady=10)

        # Toggle Options
        self.vulnscan_var = ctk.BooleanVar(value=True)
        self.exploit_var = ctk.BooleanVar(value=False)
        self.privesc_var = ctk.BooleanVar(value=False)

        self.chk_vulnscan = ctk.CTkCheckBox(self, text="Vulnerability Scan", variable=self.vulnscan_var)
        self.chk_exploit = ctk.CTkCheckBox(self, text="Exploit Detected Vulnerabilities", variable=self.exploit_var)
        self.chk_privesc = ctk.CTkCheckBox(self, text="Attempt Privilege Escalation", variable=self.privesc_var)

        self.chk_vulnscan.grid(row=2, column=0, pady=5, sticky="w", padx=40)
        self.chk_exploit.grid(row=2, column=1, pady=5, sticky="e", padx=40)
        self.chk_privesc.grid(row=2, column=0, columnspan=2, pady=5)

        # Output Text Box
        self.log_text = ctk.CTkTextbox(self, width=540, height=250, corner_radius=8)
        self.log_text.grid(row=3, column=0, columnspan=2, padx=20, pady=(10, 20))
        self.log_text.insert("end", "Welcome to the Automated Pentesting Tool GUI\n")
        self.log_text.configure(state="disabled")

        # Run Button
        self.run_button = ctk.CTkButton(self, text="🚀 Run Pentest", command=self.run_pentest_thread)
        self.run_button.grid(row=4, column=0, columnspan=2, pady=(0, 20))

    def run_pentest_thread(self):
        threading.Thread(target=self.run_pentest).start()

    def run_pentest(self):
        target = self.target_entry.get().strip()
        if not target:
            self.append_log("[ERROR] No target entered.")
            return

        self.append_log(f"[INFO] Starting pentest on {target}...\n")

        recon_data = run_recon(target)
        self.append_log(f"[RECON] Open ports: {recon_data.get('open_ports', [])}")

        model = init_model()
        predictions = classify_vulnerabilities(model, recon_data)
        self.append_log(f"[AI] Predicted vulnerabilities: {predictions}")

        vuln_info = {"found_vulns": []}
        if self.vulnscan_var.get():
            vuln_info = run_vuln_scan(target, recon_data)
            self.append_log(f"[VULNSCAN] Found: {vuln_info.get('found_vulns', [])}")
        else:
            self.append_log("[VULNSCAN] Skipped.")

        exploit_result = {}
        if self.exploit_var.get():
            exploit_result = run_exploit(target, vuln_info)
            if exploit_result.get("success"):
                self.append_log("[EXPLOIT] Exploit succeeded.")
            else:
                self.append_log("[EXPLOIT] Exploit failed or no vulnerabilities found.")
        else:
            self.append_log("[EXPLOIT] Skipped.")

        if self.privesc_var.get() and exploit_result.get("success"):
            run_priv_esc(exploit_result)
            self.append_log("[PRIVESC] Attempted privilege escalation.")
        elif self.privesc_var.get():
            self.append_log("[PRIVESC] Skipped due to no shell access.")
        else:
            self.append_log("[PRIVESC] Skipped.")

        self.append_log("[DONE] Pentest workflow complete.\n")

    def append_log(self, message):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"{message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

if __name__ == "__main__":
    app = PentestApp()
    app.mainloop()
