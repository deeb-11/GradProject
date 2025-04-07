# GradProject

# 🛡️ AI-Powered Automated Penetration Testing Tool

This project is an intelligent, modular penetration testing tool developed for educational and research purposes. Built using Python and tested on Kali Linux, the tool automates multiple phases of offensive security testing — including reconnaissance, vulnerability classification (via AI), simulated exploitation, and optional privilege escalation — all from a sleek graphical interface.

---

## 📌 Project Overview

- **Type**: Dissertation / Research Project  
- **Environment**: Kali Linux (Python 3.11+, Nmap, Sublist3r)  
- **Interface**: CustomTkinter (Modern Python GUI)  
- **AI**: RandomForestClassifier trained on vulnerability dataset  
- **Ethics**: Approved by Coventry University, tested only on legal/sandboxed systems  

---

## 🧠 Features

- 🔍 **Automated Reconnaissance**: Scans for open ports, services, OS info  
- 🧠 **AI-Based Classification**: Predicts likely vulnerabilities from recon output  
- 💣 **Simulated Exploitation**: Matches services to known CVEs (non-destructive)  
- 🔐 **Privilege Escalation** (optional): Basic local enum post-exploit  
- 🖥️ **GUI Interface**: User-friendly input and real-time log viewer  
- 📁 **Modular Design**: Each component is independently testable

---

## 🛠️ Installation Steps

Follow these steps to set up and run the Automated Pentesting Tool on **Kali Linux**:

### 1. Prepare the Project Directory

If you haven’t already, create a directory and place your source folders inside:

```bash
mkdir PenTest_Automation
cd PenTest_Automation
```

Ensure the following folders/files are in place:
- `ai_core/`
- `recon/`
- `vulnscan/`
- `exploit/`
- `privesc/`
- `ui/` (contains `ui_interface.py`)
- `data/` (contains `vuln_data.csv`)

---

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

---

### 3. Install Python Dependencies

Use pip to install the required Python libraries:

```bash
pip install scikit-learn pandas numpy customtkinter python-nmap
```

---

### 4. Install External Tools (If Needed)

Make sure `nmap` and `sublist3r` are installed (most are pre-installed on Kali):

```bash
sudo apt update
sudo apt install nmap sublist3r
```

---

### 5. Run the Tool

Start the graphical interface from your main directory:

```bash
python src/ui/ui_interface.py
```

---

## 📂 Project Structure

```
PenTest_Automation/
├── data/
│   └── vuln_data.csv          # Training dataset for AI model
├── ai_core/
│   └── classifier.py          # Model logic and prediction
├── recon/
│   └── recon_main.py
├── vulnscan/
│   └── scan_main.py
├── exploit/
│   └── exploit_main.py
├── privesc/
│   └── priv_esc.py
├── ui/
│   └── ui_interface.py        # Main GUI entry point
├── logs/
└── README.md
```

---

## 🧪 Testing Environments

✅ **Metasploitable2**  
✅ **TryHackMe** Labs (via VPN)  
✅ **Dummy IPs** for error handling validation  

> ⚠️ This tool must **only be used in safe, legal environments**. Do not scan or exploit public systems.

---

## 🔒 Legal & Ethical Notice

This tool was developed solely for **academic and educational use**. It was tested in line with the **Computer Misuse Act 1990** and institutional ethical guidelines. All exploit actions are simulated; no payloads or real attacks are executed.

---

## 📈 Future Enhancements

- API integration with ExploitDB/NVD
- Real-time CVE updates to AI model
- Stealth scan tuning for IDS evasion
- AI module for privilege escalation prediction
- Web-based GUI deployment

---

## 👨‍🎓 Author

**Name**: _[AbdAllah ElDeib]_  
**University**: Coventry University  
**Course**: BSc Ethical Hacking & Cybersecurity  
**Supervisor**: _[Kabiru Mohammed]_

---


