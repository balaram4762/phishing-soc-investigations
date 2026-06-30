#!/usr/bin/env python3
"""
SOC Analyst IOC Organizer
Phishing Email Investigation Project

Used this mainly as a working example for PHI-001. The rest of the
cases (PHI-002 to PHI-005) I did manually by checking each URL on
VirusTotal directly and writing up the findings in the case files.
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
#  Five phishing cases investigated
# ─────────────────────────────────────────────

CASES = [
    new_case(
        case_id="PHI-001",
        subject="Fake Sahibinden shopping site",
        sender="sahibinden.elektronik-magaza-sepetim.com",
        date_reported="2026-06-29"
    ),
    new_case(
        case_id="PHI-002",
        subject="Fake Carrefour promo page",
        sender="carrefour.negocie-aqui.com",
        date_reported="2026-06-29"
    ),
    new_case(
        case_id="PHI-003",
        subject="Fake medical solutions site",
        sender="unitedmedicalsolutions.org",
        date_reported="2026-06-29"
    ),
    new_case(
        case_id="PHI-004",
        subject="Fake iCloud unlock bypass service",
        sender="icloud-unlock-bypass.com",
        date_reported="2026-06-29"
    ),
    new_case(
        case_id="PHI-005",
        subject="Fake Smart Fit ad page",
        sender="smartfitbr.com",
        date_reported="2026-06-29"
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
                    "ioc_type": ioc_type.rstrip("s"),
                    "ioc_value": v,
                    "severity": c["severity"],
                    "date_reported": c["date_reported"]
                })
    if not rows:
        print("[!] No IOC rows to export yet")
        return
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    print(f"[✓] CSV exported  → {out_path}  ({len(rows)} IOC rows)")


def export_markdown_summary(cases, out_path="reports/IOC_MASTER_LIST.md"):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# IOC List - all cases combined",
        f"Generated: {datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n",
        "---\n"
    ]
    for c in cases:
        lines.append(f"## {c['case_id']} — {c['subject']}")
        lines.append(f"- Domain/Sender: `{c['sender']}`")
        lines.append(f"- Attack type: {c['attack_type'] or 'TBD'}")
        lines.append(f"- Severity: {c['severity'] or 'TBD'}")
        lines.append(f"- Recommendation: {c['recommendation'] or 'TBD'}\n")
        lines.append("### IOCs")
        for ioc_type, values in c["iocs"].items():
            if values:
                lines.append(f"\n**{ioc_type}**")
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

Case ID: {case_id}
Date: {date_reported}
Severity: {severity}
Attack Type: {attack_type}

## Email/site details
Subject: {subject}
Sender/domain: {sender}

## Findings
{findings}

## Tools used
{tools_list}

## IOCs

IPs:
{ioc_ips}

Domains:
{ioc_domains}

URLs:
{ioc_urls}

Email addresses:
{ioc_emails}

File hashes:
{ioc_hashes}

## Recommendation
{recommendation}

---
Analyst: [Your Name] | {date_reported}
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
        findings=case["findings"] or "Findings pending.",
        tools_list="\n".join(f"- {t}" for t in case["tools_used"]) or "- TBD",
        ioc_ips=fmt_list(case["iocs"]["ips"]),
        ioc_domains=fmt_list(case["iocs"]["domains"]),
        ioc_urls=fmt_list(case["iocs"]["urls"]),
        ioc_emails=fmt_list(case["iocs"]["email_addresses"]),
        ioc_hashes=fmt_list(case["iocs"]["file_hashes"]),
        recommendation=case["recommendation"] or "Pending."
    )

    path = f"{out_dir}/{case['case_id']}.md"
    with open(path, "w") as f:
        f.write(content)
    print(f"[✓] Ticket created → {path}")


# ─────────────────────────────────────────────
#  Main — example run using PHI-001 real data
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("\n=== SOC Phishing Investigation — IOC Organizer ===\n")

    c1 = CASES[0]
    c1["attack_type"] = "credential_phishing"
    c1["severity"] = "HIGH"
    c1["tools_used"] = ["VirusTotal", "PhishTank"]
    c1["findings"] = (
        "Fake Sahibinden site. Domain registered same day as the attack. "
        "Flagged by 4/92 vendors on VirusTotal (Emsisoft, Fortinet, Netcraft, SOCRadar). "
        "Hosted behind Cloudflare to hide the real server location."
    )
    c1["recommendation"] = (
        "Block domain at firewall. Report URL to PhishTank. "
        "Alert any users who clicked the link."
    )
    add_ioc(c1, "domains", "sahibinden.elektronik-magaza-sepetim.com")
    add_ioc(c1, "urls", "http://sahibinden.elektronik-magaza-sepetim.com/adres")
    add_ioc(c1, "ips", "104.21.20.125")

    for case in CASES:
        generate_ticket(case)

    export_json(CASES)
    export_csv(CASES)
    export_markdown_summary(CASES)

    print("\n[✓] Done. PHI-001 has real findings filled in as an example.")
    print("    PHI-002 through PHI-005 were investigated and written up")
    print("    manually in their own case files.\n")
