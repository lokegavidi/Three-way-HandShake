
# 🛡️ TCP Handshake Analyzer

A Python-based mini project to capture, analyze, and detect anomalies in TCP 3-way handshakes. Designed for SOC Analysts, Cybersecurity learners, and network defenders.

---

## 📌 Overview
This tool uses **Scapy** to sniff live TCP traffic, analyze the handshake process, and detect suspicious behaviors like:
- SYN Flood Attacks
- Half-open TCP Connections
- Repeated SYN attempts (potential scanning or DoS)

---

## 🎯 Project Goals
- Understand TCP 3-Way Handshake in-depth
- Learn how to capture and inspect TCP packets
- Detect SYN Flood attempts using timing and count logic
- Generate alert logs for suspicious IPs

---

## 🧰 Requirements
- Python 3.x
- Admin privileges (required for raw packet sniffing)
- Scapy

### 📦 Installation
```bash
pip install scapy
```

---

## 🚀 How It Works
1. Sniffs all TCP packets on your network interface
2. Analyzes TCP flags:
   - `S` for SYN
   - `SA` for SYN-ACK
   - `A` for ACK
3. Tracks the number and timing of SYN packets per source IP
4. If more than 10 SYNs in 5 seconds: **alerts a possible SYN flood**

---

## 📜 Code File: `tcp_analyzer.py`
```python
from scapy.all import sniff, TCP, IP
from collections import defaultdict
import time

syn_tracker = defaultdict(list)

def analyze_packet(pkt):
    if pkt.haslayer(TCP) and pkt.haslayer(IP):
        ip_src = pkt[IP].src
        ip_dst = pkt[IP].dst
        flags = pkt[TCP].flags

        if flags == 'S':
            syn_tracker[ip_src].append(time.time())
            print(f"[+] SYN from {ip_src} to {ip_dst}")

        elif flags == 'SA':
            print(f"[+] SYN-ACK from {ip_src} to {ip_dst}")

        elif flags == 'A':
            print(f"[+] ACK from {ip_src} to {ip_dst}")

        # Detect SYN Flood
        for ip, timestamps in syn_tracker.items():
            recent = [t for t in timestamps if time.time() - t < 5]
            if len(recent) > 10:
                with open("suspicious_log.txt", "a") as f:
                    alert = f"[!] SYN Flood suspected from {ip} - {len(recent)} SYNs in 5 seconds\n"
                    print(alert)
                    f.write(alert)
                syn_tracker[ip] = []

print("[*] Starting packet capture... Press Ctrl+C to stop.")
sniff(filter="tcp", prn=analyze_packet, store=False)
```

---

## 📁 Output
- Console logs of SYN, SYN-ACK, ACK packets
- Suspicious activity written to `suspicious_log.txt`

---

## 📈 Sample Output
```txt
[+] SYN from 192.168.0.101 to 93.184.216.34
[+] SYN-ACK from 93.184.216.34 to 192.168.0.101
[+] ACK from 192.168.0.101 to 93.184.216.34
[!] SYN Flood suspected from 192.168.0.150 - 15 SYNs in 5 seconds
```

---

## 🔧 Project Ideas for Extension
- Detect port scans (many SYNs to different ports)
- Visualize connections using Streamlit or Matplotlib
- Auto block IP using firewall rules
- Export alerts to CSV or send Slack/email notifications

---

## 👨‍💻 Author
**Gavidi Lokesh**  
Cybersecurity Enthusiast | SOC Analyst

---

## 🏷 Hashtags for GitHub/LinkedIn
```
#CyberSecurity #SOCAnalyst #TCPHandshake #PythonProject #PacketSniffing #Scapy #Networking #MiniProject
```

---

## 📜 License
MIT License
