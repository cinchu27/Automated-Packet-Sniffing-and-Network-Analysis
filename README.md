# 🔐 Automated-Packet-Sniffing-and-Network-Analysis


## 📌 Introduction
This project demonstrates **core network security operations** automated using Python.
It combines **packet sniffing**, **firewall configuration concepts**, and **vulnerability
scanning awareness** to analyze and assess a Linux-based network environment.

The primary focus of this repository is **Python-based automation for packet analysis**
using Scapy, along with an understanding of how firewall rules and vulnerability scanners
contribute to overall network security.

This project is intended as a **cybersecurity portfolio project**.

---

## 📡 Packet Sniffing with Scapy
Packet sniffing is implemented using **Scapy**, a powerful Python library for packet
manipulation and analysis.

The Python script:
- Captures live network traffic
- Identifies protocols such as TCP, UDP, ICMP, and non-IP traffic
- Extracts packet summaries in real time
- Maintains protocol statistics during capture

This demonstrates **low-level traffic inspection and protocol analysis**.

---

## 🔥 Firewall Configuration with iptables
Firewall configuration concepts are explored using **iptables** to understand how
network traffic can be restricted and controlled.

Key concepts covered:
- Allowing trusted services
- Blocking unnecessary ports
- Reducing attack surface
- Understanding rule order and traffic flow

Firewall behavior is validated through traffic observation and scanning.

---

## 🔍 Vulnerability Scanning with OpenVAS
Vulnerability scanning concepts are demonstrated using **OpenVAS**, an enterprise-grade
vulnerability assessment tool.

Activities include:
- Running vulnerability scans against a target system
- Identifying exposed services and misconfigurations
- Interpreting severity levels and potential risks
- Understanding remediation recommendations

This section highlights **defensive security assessment practices**.

---

## 🐍 Python Automation Script
This repository includes a Python script that automates **packet sniffing and traffic
analysis** using Scapy.

### Script Capabilities
- Captures a fixed number of packets
- Classifies packets by protocol (TCP, UDP, ICMP, Other)
- Displays real-time packet summaries
- Generates protocol statistics
- Creates a visual bar chart of protocol distribution

The script also produces a visualization file:
```text
protocol_distribution.png

```
📥 Installation & Setup

Install required system tools:
```bash
sudo apt update
sudo apt install python3 wireshark nmap iptables
```
Install Python dependencies:
```bash
pip install -r requirements.txt
```
▶️ Usage

Run the automation script with administrative privileges:
```bash
sudo python3 automate_security_tasks.py
 ```
📄 Output

The script produces:
- Real-time packet summaries in the terminal
- Protocol statistics after capture
- A bar chart visualization saved as:
```text
protocol_distribution.png

```
⚠️ Disclaimer

This project is for educational purposes only.
Only analyze or scan systems you own or have explicit permission to test.
Unauthorized packet sniffing, firewall manipulation, or vulnerability scanning
is illegal and unethical.

