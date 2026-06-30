# 🛡️ Phishing Email Investigation — SOC Analyst Case Files

A portfolio project demonstrating real-world SOC analyst workflows: collecting publicly-reported phishing samples, analyzing them with free industry tools, extracting IOCs, and writing professional investigation tickets.

> **All samples used are already-reported public threat intelligence from PhishTank. No live malware is downloaded or executed.**

---

## 📁 Project Structure

---

## 🔧 Tools Used

| Tool | Purpose |
|------|---------|
| [PhishTank](https://phishtank.org) | Source of real, currently-reported phishing URLs |
| [VirusTotal](https://virustotal.com) | Scan URLs and IPs against 90+ security vendors |

---

## 📋 Case Summary

| Case ID | Brand Impersonated | Attack Type | Detection Score | Server IP |
|---------|---------------------|-------------|------------------|-----------|
| PHI-001 | Sahibinden | Credential Phishing | 4/92 | 104.21.20.125 |
| PHI-002 | Carrefour | Credential Phishing | 1/92 | 13.32.205.46 |
| PHI-003 | United Medical Solutions | Credential Phishing | 16/92 | 216.55.149.9 |
| PHI-004 | Apple iCloud | Credential Phishing | 3/90 | 69.16.230.228 |
| PHI-005 | Smart Fit | Credential Phishing | 5/92 | 172.67.169.143 |

---

## 🔍 Analysis Workflow (per case)

1. **Sample collection** — sourced live, verified phishing URLs from PhishTank
2. **URL reputation check** — submitted each URL to VirusTotal, recorded vendor detection count
3. **IP investigation** — extracted the hosting server IP from VirusTotal's Details tab, checked IP reputation and hosting provider
4. **IOC extraction** — recorded domain, URL, and IP for each case
5. **Ticket writing** — documented findings, severity, and remediation steps in a structured Markdown ticket per case

---

## 📖 What I Learned

- How to source real-time phishing threat intelligence from PhishTank
- How to use VirusTotal to check URL and IP reputation across 90+ security vendors
- Why newly-registered phishing domains often show 0 detections initially, and why that doesn't mean they're safe
- How attackers use trusted cloud providers (Cloudflare, AWS) to host phishing infrastructure and avoid suspicion
- How to identify brand impersonation patterns (typosquatting, lookalike domains)
- How to write structured SOC investigation tickets with IOCs and remediation recommendations

---

*Built as a cybersecurity portfolio project. All threat data sourced from public, community-reported repositories on PhishTank.*
