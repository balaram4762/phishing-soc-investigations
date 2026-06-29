# SOC Analyst Workflow — Step-by-Step Analysis Guide

Use this checklist for every phishing sample you investigate.
Check off each step as you complete it.

---

## STEP 1 — Find a sample on PhishTank or Any.run

### PhishTank
1. Go to https://phishtank.org/phish_search.php
2. Filter by "verified" phishes
3. Click on a listing — note the phishing URL and the brand it impersonates
4. DO NOT visit the phishing URL directly in your browser

### Any.run (for emails with attachments)
1. Go to https://any.run/malware-trends/
2. Search for "phishing" in the public task feed
3. Open a task — you will see the detonation results (safe to view)
4. Note: the Process Tree, Network tab, and IOC tab are your key sections

**What to record at this step:**
- The phishing URL or email subject
- The brand being impersonated
- Date reported / date submitted

---

## STEP 2 — Analyze the email header with MXToolbox

If you have access to raw email headers (Any.run often shows these):

1. Go to https://mxtoolbox.com/EmailHeaders.aspx
2. Paste the raw headers
3. Look for these specific results:

| Check | What it means if it FAILS |
|-------|--------------------------|
| SPF   | Sender IP not authorized to send for that domain |
| DKIM  | Email content was not signed by the real domain |
| DMARC | Domain has no policy, or policy was violated |

**What to record:**
- SPF result (PASS / FAIL / SOFTFAIL)
- DKIM result (PASS / FAIL / NONE)
- DMARC result
- The "From" header vs the "Return-Path" — do they match?
- The originating IP address (look for "Received: from" lines)

---

## STEP 3 — Scan URLs with URLScan.io

1. Go to https://urlscan.io
2. Paste the suspicious URL (the one from the phishing email)
3. Click Scan — wait 30 seconds
4. Review the results:

**Key things to look at:**
- **Screenshot tab** — does it show a fake login page?
- **Summary tab** — what country/ASN is the server in?
- **DOM tab** — look for password field forms, suspicious JS
- **HTTP tab** — look for redirects (often 2–3 hops before the final page)
- **Indicators tab** — URLScan lists IPs, domains, and hashes it found

**What to record:**
- Final destination URL (after all redirects)
- Server IP
- ASN / hosting provider
- Whether a login form is present (credential phishing indicator)
- Any secondary domains loaded by the page

---

## STEP 4 — Check reputation on VirusTotal

### For URLs:
1. Go to https://virustotal.com
2. Click URL tab → paste the URL → press Enter
3. Read the Detection tab — how many vendors flag it?
   - 0–2 flags: possibly clean or very new
   - 3–9 flags: suspicious
   - 10+ flags: confirmed malicious
4. Check the Relations tab for connected IPs and domains

### For IPs (from URLScan or email header):
1. Click IP Address tab on VirusTotal
2. Paste the IP
3. Check: Detection score, ASN, country, passive DNS (what other domains pointed here?)

### For file hashes (if Any.run gave you one):
1. Click File tab → paste the MD5 or SHA256 hash
2. Read Detection + Behavior tabs

**What to record:**
- Detection score (e.g. "18/90 vendors")
- Any AV vendor names that flagged it and what they called it
- Related domains/IPs from the Relations tab
- File type and behavior summary (for hashes)

---

## STEP 5 — Check any attachment on Any.run

If the email had an attachment (PDF, .docx, .zip, .exe):

1. Search Any.run public tasks for the file name or hash
2. Open the task and review:
   - **Process Tree** — what processes did the file launch?
   - **Network** — did it make outbound connections? To where?
   - **IOC tab** — Any.run automatically lists extracted IOCs
   - **Screenshots** — did it show a fake document or login?

**Red flags to note:**
- PowerShell or cmd.exe launched by Word/PDF reader (macro execution)
- Outbound connections to unusual IPs/domains
- File drops in Temp or AppData folders
- Registry persistence keys created

**What to record:**
- File name and hash (MD5 + SHA256)
- Processes spawned
- Network connections made (IPs + domains)
- Files dropped
- Persistence mechanisms if any

---

## STEP 6 — Extract all IOCs

Open `scripts/ioc_organizer.py` and fill in the case data:

```python
c = CASES[0]  # change index for each case
c["attack_type"] = "credential_phishing"   # or malware_delivery
c["severity"] = "HIGH"
c["tools_used"] = ["MXToolbox", "URLScan.io", "VirusTotal"]
c["findings"] = "Describe what you found here..."
c["recommendation"] = "What should be done..."

add_ioc(c, "domains",          "fake-domain.com")
add_ioc(c, "urls",             "http://fake-domain.com/login.php")
add_ioc(c, "ips",              "1.2.3.4")
add_ioc(c, "email_addresses",  "attacker@fake-domain.com")
add_ioc(c, "file_hashes",      "d41d8cd98f00b204e9800998ecf8427e")
```

Then run: `python3 scripts/ioc_organizer.py`

---

## STEP 7 — Write the SOC ticket

Open the generated `cases/PHI-00X.md` file and fill in:

1. **Summary of Findings** — 3–5 sentences explaining what the email is doing
2. **Tools Used** — list each tool and the key result it gave
3. **IOCs** — already populated by the script
4. **Recommendation** — pick from these standard actions:
   - Block domain at email gateway
   - Null-route IP at firewall
   - Report URL to PhishTank/Google SafeBrowsing
   - Alert users who received the email
   - Submit file hash to AV vendor
   - Reset credentials of affected users

---

## Attack Type Reference

| Type | Description | Key Indicators |
|------|-------------|----------------|
| Credential Phishing | Fake login page steals username/password | Login form, brand impersonation, urgency language |
| Malware Delivery | Attachment or link installs malware | .exe/.zip/.docx attachment, PowerShell in process tree |
| BEC (Business Email Compromise) | Impersonates executive to request action | No link/attachment, spoofed display name, wire transfer request |
| Smishing/Vishing redirect | Email sends to SMS or phone | Phone number in body, no embedded link |

---

## Severity Rating Guide

| Rating | Criteria |
|--------|----------|
| LOW | URL already taken down, no known victims |
| MEDIUM | Active page, generic lure, limited targeting |
| HIGH | Active credential harvester, brand impersonation, wide distribution |
| CRITICAL | Malware delivery, persistence mechanisms, active C2 communication |

---

*Complete one case per sitting. 5 cases = full project portfolio.*
