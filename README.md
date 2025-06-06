# 🧠 Suricata + MITRE ATT&CK Mapping — Know Thy Enemy

> “If you know the enemy and know yourself, you need not fear the result of a hundred battles.”  
> — Sun Tzu, probably after enabling Suricata with custom rule mappings.

This project turns your Suricata alerts into actionable threat intel, directly mapped to the [MITRE ATT&CK](https://attack.mitre.org/) framework. No more guessing — every alert tells you **who**, **what**, and **how**.

Welcome to your **Suricata + ATT&CK Threat Intelligence Lab**, where detection becomes insight:  
- 🕵️ Suricata to catch the bad guys  
- 🧩 MITRE ATT&CK to understand their behavior  
- 📈 Tactical awareness that hits harder than any IDS alert alone  

---

## 🔍 What This Project Does

- Integrates **Suricata IDS** with MITRE ATT&CK mapping  
- Classifies alerts by **Tactics** (Initial Access, Execution, etc.) and **Techniques** (T1046, T1059…)  
- Generates **enriched logs** with ATT&CK context for faster triage  
- Enables **SOC analysts** and blue teamers to understand attacker objectives in real time  

---

## 🧰 Prerequisites

- A working Suricata installation (`suricata.yaml` configured properly)  
- JSON logging enabled (EVE output):  
  ```yaml
  outputs:
    - eve-log:
        enabled: yes
        filetype: regular
        filename: /var/log/suricata/eve.json
        types:
          - alert:
              metadata: yes
  ```  
- Python 3 for log parsing and enrichment  
- MITRE ATT&CK mapping source (CSV, STIX, or custom JSON dictionary)

---

## ⚙️ How It Works

1. Suricata generates JSON alerts in `eve.json`  
2. A Python parser reads each alert  
3. Alerts with metadata or known rule SIDs are matched to MITRE TTPs  
4. Outputs a new enriched log with Tactics and Techniques included  

---

## 🧠 Example Output

```json
{
  "timestamp": "2025-06-06T15:23:01.123Z",
  "src_ip": "192.168.1.100",
  "dest_ip": "10.0.0.2",
  "alert": {
    "signature": "ET SCAN Nmap -sS window 1024",
    "category": "Attempted Information Leak",
    "metadata": {
      "attack_technique": "T1046",
      "attack_tactic": "Discovery"
    }
  }
}
```

---

## 🗂️ MITRE Mapping Tips

- Use open-source sources like [Sigma rules](https://github.com/SigmaHQ/sigma) or [Elastic’s ATT&CK mappings](https://github.com/elastic/detection-rules)  
- Build a dictionary mapping `signature_id` → `TTP` (Tactic, Technique, Sub-technique)  
- Maintain your mappings in a JSON or CSV like:  
  ```csv
  sid,technique_id,tactic
  2021001,T1046,Discovery
  2022002,T1059,Execution
  ```

---

## 📊 Visualization Options

- Use ELK stack (Elasticsearch, Logstash, Kibana)  
- Tag Suricata alerts with MITRE fields and create dashboards:  
  - Top Tactics over time  
  - Technique frequency  
  - Attacker kill chain progression  

---

## 🧪 Test Techniques

Simulate TTPs using tools like:  
- `Atomic Red Team`  
- `Invoke-ATTACKAPI`  
- Custom Metasploit modules  
- Manual Nmap, Netcat, PowerShell commands  

This gives you real-world attack data mapped in your logs.

---

## 🚨 Why This Matters

Raw IDS alerts aren’t enough anymore.  
Security teams need **context**, and attackers don’t wait for you to catch up.  
This project bridges the gap between detection and intel-driven defense.

---

## 👤 About Me

I'm Gunveer Singh (`vlain-jkr`) — giving Suricata a tactical brain and hunting with purpose.  
I don't just want alerts — I want a story, a map, a mission log of every attacker foolish enough to touch the wire.

---

*Fork it, run it, expand it. Know the technique. Stop the breach. Rule your logs.*
