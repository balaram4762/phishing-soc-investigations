#!/usr/bin/env python3
"""
SOC Analyst IOC Organizer
Phishing Email Investigation Project
"""

import json
import csv
import datetime
from pathlib import Path

# ─────────────────────────────────────────────
#  Data structure for a single phishing case
# ─────────────────────────────────────────────

def new_case(case_id, subject, sender, date_reported):
    return {
        "case_id": case_id,
        "subject": subject,
        "sender": sender,
        "date_reported": date_reported,
        "attack_type": "",          # e.g. credential_phishing / malware_delivery
        "iocs": {
            "ips": [],
            "domains": [],
            "urls": [],
            "email_addresses": [],
            "file_hashes": []
        },
        "tools_used": [],
        "findings": "",
        "recommendation": "",
        "severity": ""              # LOW / MEDIUM / HIGH / CRITICAL
    }


# ─────────────────────────────────────────────
#  Five phishing case templates — fill these
#  in as you analyze each sample
# ─────────────────────────────────────────────

CASES = [
    new_case(
        case_id="PHI-001",
        subject="Your PayPal account has been limited",
        sender="service@paypa1-support.com",
        date_reported="2024-01-10"
    ),
    new_case(
        case_id="PHI-002",
        subject="Microsoft: Unusual sign-in activity detected",
        sender="security@microsoftonline-alert.net",
        date_reported="2024-01-12"
    ),
    new_case(
        case_id="PHI-003",
        subject="DHL: Your package is on hold — action required",
        sender="noreply@dhl-delivery-update.com",
        date_reported="2024-01-15"
    ),
    new_case(
        case_id="PHI-004",
        subject="IRS: Tax refund notification",
        sender="refund@irs-gov-notice.org",
        date_reported="2024-01-18"
    ),
    new_case(
        case_id="PHI-005",
        subject="Invoice #8821 — payment overdue",
        sender="accounts@invoice-billing-portal.xyz",
        date_reported="2024-01-20"
    ),
]


# ─────────────────────────────────────────────
#  Helper — add an IOC to a case
# ─────────────────────────────────────────────

def add_ioc(case, ioc_type, value):
    """
    ioc_type: 'ips' | 'domains' | 'urls' | 'email_addresses' | 'file_hashes'
    """
    if ioc_type not in case["iocs"]:
        print(f"[!] Unknown IOC type: {ioc_type}")
        return
    if value not in case["iocs"][ioc_type]:
        case["iocs"][ioc_type].append(value)
        print(f"[+] Added {ioc_type[:-1].upper()}: {value} → {case['case_id']}")


# ─────────────────────────────────────────────
#  Export functions
# ─────────────────────────────────────────────

def export_json(cases, out_path="iocs/all_iocs.json"):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w") as f:
        json.dump(cases, f, indent=2)
    print(f"[✓] JSON exported → {out_path}")


def export_csv(cases, out_path="iocs/ioc_flat_list.csv"):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for c in cases:
        for ioc_type, values in c["iocs"].items():
            for v in values:
                rows.append({
                    "case_id": c["case_id"],
                    "attack_type": c["attack_type"],
                    "ioc_type": ioc_type.rstrip("s"),   # ips → ip, etc.
                    "ioc_value": v,
                    "severity": c["severity"],
                    "date_reported": c["date_reported"]
                })
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else [])
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] CSV exported  → {out_path}  ({len(rows)} IOC rows)")


def export_markdown_summary(cases, out_path="reports/IOC_MASTER_LIST.md"):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Phishing Investigation — Master IOC List",
        f"_Generated: {datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}_\n",
        "---\n"
    ]
    for c in cases:
        lines.append(f"## {c['case_id']} — {c['subject']}")
        lines.append(f"- **Sender:** `{c['sender']}`")
        lines.append(f"- **Attack type:** {c['attack_type'] or 'TBD'}")
        lines.append(f"- **Severity:** {c['severity'] or 'TBD'}")
        lines.append(f"- **Recommendation:** {c['recommendation'] or 'TBD'}\n")
        lines.append("### IOCs")
        for ioc_type, values in c["iocs"].items():
            if values:
                lines.append(f"\n**{ioc_type.upper()}**")
                for v in values:
                    lines.append(f"- `{v}`")
        lines.append("\n---\n")
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"[✓] Markdown summary → {out_path}")


# ─────────────────────────────────────────────
#  SOC ticket generator
# ─────────────────────────────────────────────

TICKET_TEMPLATE = """\
# SOC Investigation Ticket — {case_id}

| Field            | Value                        |
|------------------|------------------------------|
| Case ID          | {case_id}                    |
| Date Reported    | {date_reported}              |
| Severity         | {severity}                   |
| Attack Type      | {attack_type}                |

## Email Details
- **Subject:** {subject}
- **Sender:** `{sender}`

## Summary of Findings
{findings}

## Tools Used
{tools_list}

## Indicators of Compromise (IOCs)

### IP Addresses
{ioc_ips}

### Domains
{ioc_domains}

### URLs
{ioc_urls}

### Sender Email Addresses
{ioc_emails}

### File Hashes (MD5 / SHA256)
{ioc_hashes}

## Recommendation
{recommendation}

---
_Analyst: [Your Name] | {date_reported}_
"""

def generate_ticket(case, out_dir="cases"):
    Path(out_dir).mkdir(parents=True, exist_ok=True)

    def fmt_list(lst):
        return "\n".join(f"- `{v}`" for v in lst) if lst else "- None identified"

    content = TICKET_TEMPLATE.format(
        case_id=case["case_id"],
        date_reported=case["date_reported"],
        severity=case["severity"] or "PENDING",
        attack_type=case["attack_type"] or "PENDING",
        subject=case["subject"],
        sender=case["sender"],
        findings=case["findings"] or "_Findings pending analysis._",
        tools_list="\n".join(f"- {t}" for t in case["tools_used"]) or "- TBD",
        ioc_ips=fmt_list(case["iocs"]["ips"]),
        ioc_domains=fmt_list(case["iocs"]["domains"]),
        ioc_urls=fmt_list(case["iocs"]["urls"]),
        ioc_emails=fmt_list(case["iocs"]["email_addresses"]),
        ioc_hashes=fmt_list(case["iocs"]["file_hashes"]),
        recommendation=case["recommendation"] or "_Pending._"
    )

    path = f"{out_dir}/{case['case_id']}.md"
    with open(path, "w") as f:
        f.write(content)
    print(f"[✓] Ticket created → {path}")


# ─────────────────────────────────────────────
#  Main — run to generate all scaffolding
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== SOC Phishing Investigation — IOC Organizer ===\n")

    # Example: populate PHI-001 with data you find during analysis
    c1 = CASES[0]
    c1["attack_type"] = "credential_phishing"
    c1["severity"] = "HIGH"
    c1["tools_used"] = ["MXToolbox", "URLScan.io", "VirusTotal"]
    c1["findings"] = (
        "Sender domain paypa1-support.com (note digit '1' instead of letter 'l') "
        "registered 3 days before attack. SPF and DKIM both fail. "
        "Embedded link redirects to credential harvesting page mimicking PayPal login. "
        "VirusTotal: 18/90 vendors flag the domain as phishing."
    )
    c1["recommendation"] = (
        "Block domain paypa1-support.com at email gateway and DNS firewall. "
        "Report URL to PhishTank. Alert users who clicked."
    )
    add_ioc(c1, "domains",         "paypa1-support.com")
    add_ioc(c1, "urls",            "http://paypa1-support.com/verify/login.php")
    add_ioc(c1, "ips",             "185.220.101.47")
    add_ioc(c1, "email_addresses", "service@paypa1-support.com")

    # Generate skeleton tickets for all 5 cases
    for case in CASES:
        generate_ticket(case)

    # Export IOC lists
    export_json(CASES)
    export_csv(CASES)
    export_markdown_summary(CASES)

    print("\n[✓] All files generated. Fill in cases PHI-002 through PHI-005")
    print("    as you complete each analysis.\n")
