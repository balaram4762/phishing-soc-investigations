# 🛡️ Phishing Email Investigation — SOC Analyst Case Files

A portfolio project demonstrating real-world SOC analyst workflows: collecting publicly-reported phishing samples, analyzing them with free industry tools, extracting IOCs, and writing professional investigation tickets.

> **All samples used are already-reported public threat intelligence from PhishTank and Any.run. No live malware is downloaded or executed.**

---

## 📁 Project Structure

```
phishing-soc-project/
│
├── cases/                  # One SOC ticket per investigation
│   ├── PHI-001.md          # PayPal credential phishing
│   ├── PHI-002.md          # Microsoft account spoofing
│   ├── PHI-003.md          # DHL delivery lure
│   ├── PHI-004.md          # IRS tax refund scam
│   └── PHI-005.md          # Malicious invoice / malware delivery
│
├── iocs/
│   ├── all_iocs.json       # Full structured IOC data (machine-readable)
│   └── ioc_flat_list.csv   # Flat IOC list for SIEM import
│
├── reports/
│   └── IOC_MASTER_LIST.md  # Human-readable summary of all IOCs
│
└── scripts/
    └── ioc_organizer.py    # Python tool to manage, export, and ticket IOCs
```

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| [PhishTank](https://phishtank.org) | Source of verified phishing URL samples |
| [Any.run](https://any.run) | Public sandbox — view detonation results safely |
| [VirusTotal](https://virustotal.com) | Scan URLs, IPs, and file hashes |
| [URLScan.io](https://urlscan.io) | Deep scan of suspicious websites |
| [MXToolbox](https://mxtoolbox.com/EmailHeaders.aspx) | Email header analysis, SPF/DKIM checks |
| Python 3 | IOC extraction, ticket generation, CSV/JSON export |

---

## 📋 Case Summary

| Case ID | Lure Theme | Attack Type | Severity |
|---------|-----------|-------------|----------|
| PHI-001 | PayPal account limited | Credential Phishing | HIGH |
| PHI-002 | Microsoft sign-in alert | Credential Phishing | HIGH |
| PHI-003 | DHL package on hold | Credential Phishing | MEDIUM |
| PHI-004 | IRS tax refund | Credential Phishing | HIGH |
| PHI-005 | Overdue invoice | Malware Delivery | CRITICAL |

---

## 🔍 Analysis Workflow (per case)

1. **Header analysis** — paste raw headers into MXToolbox, check SPF/DKIM/DMARC
2. **URL scanning** — submit all links to URLScan.io and VirusTotal
3. **IP reputation** — look up server IPs on VirusTotal and AbuseIPDB
4. **Attachment analysis** — find sandbox results on Any.run if a file was attached
5. **IOC extraction** — run `ioc_organizer.py` to record and export findings
6. **Ticket writing** — fill in the case `.md` file with full findings

---

## 🚀 Running the IOC Organizer

```bash
python3 scripts/ioc_organizer.py
```

This will:
- Generate/refresh all 5 SOC ticket `.md` files
- Export `iocs/all_iocs.json` (structured, for SIEM ingestion)
- Export `iocs/ioc_flat_list.csv` (flat list, easy to filter)
- Regenerate `reports/IOC_MASTER_LIST.md`

---

## 📖 What I Learned

- How phishing emails spoof trusted brands using typosquat domains
- How to read email headers and identify SPF/DKIM failures
- How to use VirusTotal, URLScan.io, and sandbox reports professionally
- How to write structured SOC investigation tickets
- How to extract and organize IOCs in machine-readable formats

---

*Built as a cybersecurity portfolio project. All threat data sourced from public, community-reported repositories.*
