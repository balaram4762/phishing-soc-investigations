# Phishing Email Investigation — SOC Analyst Case Files

A hands-on SOC analyst project where I investigated 5 real phishing URLs collected from open-source threat feeds. Each case was analyzed manually using free tools and documented as a structured SOC investigation ticket — exactly how a real L1 SOC analyst would handle a phishing alert.

---

## Tools Used

| Tool | Purpose |
|------|---------|
| **PhishTank** | Source for real reported phishing URLs |
| **VirusTotal** | Check URLs and IPs against 90+ security vendors |
| **Python (ioc_organizer.py)** | Auto-generate ticket templates and export IOCs to JSON/CSV |

---

## What I Did For Each Case

For every phishing URL I investigated:

1. Collected the phishing URL from PhishTank
2. Submitted the URL to VirusTotal and checked detection score
3. Found the server IP hosting the phishing page
4. Looked up the IP on VirusTotal to check for malicious history
5. Noted what brand was being impersonated
6. Extracted IOCs — domain, URL, server IP
7. Wrote a structured SOC investigation ticket with findings and recommended action

---

## Cases Summary

| Case | Brand Impersonated | Phishing URL Detection | Server IP | Severity |
|------|-------------------|----------------------|-----------|----------|
| PHI-001 | Sahibinden (Turkish marketplace) | 4/92 vendors | 104.21.20.125 | Medium |
| PHI-002 | Carrefour (Retail) | 1/92 vendors | 13.32.205.46 | Low-Medium |
| PHI-003 | Fake Medical Site | 16/92 vendors | 216.55.149.9 | High |
| PHI-004 | Apple iCloud | 3/90 vendors | 69.16.230.228 | Medium |
| PHI-005 | Smart Fit (Fitness brand) | 5/92 vendors | 172.67.169.143 | Medium |

---

## Master IOC List

All indicators of compromise extracted across all 5 cases:

| IOC Type | Value | Case |
|----------|-------|------|
| Server IP | 104.21.20.125 | PHI-001 |
| Server IP | 13.32.205.46 | PHI-002 |
| Server IP | 216.55.149.9 | PHI-003 |
| Server IP | 69.16.230.228 | PHI-004 |
| Server IP | 172.67.169.143 | PHI-005 |

Full IOC list with domains and URLs is in the `/cases` folder for each individual case.

---

## Key Findings From This Investigation

- New phishing domains often show 0 or very low detection scores on VirusTotal because nobody has reported them yet. Low score does not mean safe.
- Attackers commonly host phishing pages on Cloudflare and AWS infrastructure because it makes them harder to block and appears more legitimate to victims.
- Domain registration date is a major red flag. If a domain was registered the same day as the reported phishing attack, it is almost certainly malicious.
- Brand impersonation targets well-known companies like Apple and Carrefour because victims trust those names and are more likely to enter credentials.
- The fake medical site (PHI-003) had the highest detection score (16/92) suggesting it had been active longer and more vendors had flagged it.

---

## Sample SOC Investigation Ticket — PHI-001

**Ticket ID:** PHI-001
**Date:** 2026
**Analyst:** Balaram Reddy Venna
**Status:** Closed

**Brand Impersonated:** Sahibinden (popular Turkish online marketplace)

**Findings:**
- Phishing URL submitted to VirusTotal — 4 out of 92 vendors flagged as malicious
- Server IP 104.21.20.125 identified as hosting the phishing page
- IP linked to Cloudflare infrastructure — commonly abused by attackers
- Domain appeared newly registered — high suspicion indicator

**IOCs:**
- Phishing URL: (reported on PhishTank)
- Server IP: 104.21.20.125

**Attack Type:** Credential phishing — fake login page impersonating Sahibinden

**Severity:** Medium

**Recommended Action:** Block the phishing domain at the web proxy. Add server IP to blocklist. Report URL to VirusTotal community for wider detection coverage.

---

## What I Learned

- How to use VirusTotal beyond basic URL scanning — checking the Details tab for IP info and the Relations tab for connected infrastructure
- How to identify low-detection phishing URLs that automated tools miss
- How attackers abuse trusted cloud infrastructure like Cloudflare and AWS
- How to extract and document IOCs in a structured format
- How to write a SOC investigation ticket that is clear, actionable, and follows real analyst format
- How to build a Python script to automate IOC organization and export to JSON/CSV

---

## Project Structure

```
phishing-soc-investigations/
├── README.md
├── cases/
│   ├── PHI-001-Sahibinden.md
│   ├── PHI-002-Carrefour.md
│   ├── PHI-003-Medical.md
│   ├── PHI-004-Apple-iCloud.md
│   └── PHI-005-SmartFit.md
├── ioc_organizer.py
└── iocs/
    ├── master_ioc_list.csv
    └── master_ioc_list.json
```

---

## Disclaimer

All phishing URLs investigated in this project were already publicly reported by other users on PhishTank. No attacks were performed. This project is purely defensive — analyzing existing reported threats for educational and portfolio purposes.

---

## Author

**Balaram Reddy Venna**
Aspiring SOC Analyst | Bengaluru, Karnataka
Email: vennabalaramreddy@gmail.com
LinkedIn: linkedin.com/in/balaram6
