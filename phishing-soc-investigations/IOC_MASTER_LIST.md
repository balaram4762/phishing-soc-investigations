# IOC Master List — Phishing Investigation Project

A consolidated list of all Indicators of Compromise (IOCs) extracted across 5 SOC investigation cases. Use this list for quick firewall blocking, email gateway rules, or SIEM ingestion.

_Last updated: 2026-06-29_

---

## 🌐 Malicious Domains

| Domain | Case ID | Brand Impersonated |
|---|---|---|
| `sahibinden.elektronik-magaza-sepetim.com` | PHI-001 | Sahibinden |
| `carrefour.negocie-aqui.com` | PHI-002 | Carrefour |
| `unitedmedicalsolutions.org` | PHI-003 | Medical services (generic) |
| `icloud-unlock-bypass.com` | PHI-004 | Apple iCloud |
| `smartfitbr.com` | PHI-005 | Smart Fit |

---

## 🔗 Malicious URLs

| URL | Case ID |
|---|---|
| `http://sahibinden.elektronik-magaza-sepetim.com/adres` | PHI-001 |
| `https://carrefour.negocie-aqui.com/` | PHI-002 |
| `https://unitedmedicalsolutions.org` | PHI-003 |
| `http://www.icloud-unlock-bypass.com` | PHI-004 |
| `https://www.smartfitbr.com/?gad_source=1&gad_campaignid=2392987030` | PHI-005 |

---

## 🖥️ Malicious / Suspicious IP Addresses

| IP Address | Hosting Provider | Detection Score | Case ID |
|---|---|---|---|
| `104.21.20.125` | Cloudflare, Inc. | 0/90 (4 malicious files linked) | PHI-001 |
| `13.32.205.46` | Amazon AWS (US) | 0/91 (4 malicious files linked) | PHI-002 |
| `216.55.149.9` | Internet Names For Business Inc. | 1/92 | PHI-003 |
| `69.16.230.228` | — | 1/90 | PHI-004 |
| `172.67.169.143` | Likely Cloudflare | — | PHI-005 |

---

## 📊 Summary Statistics

- **Total cases investigated:** 5
- **Total unique domains:** 5
- **Total unique IPs:** 5
- **Attack type breakdown:** 5/5 Credential Phishing
- **Highest detection score:** PHI-003 (16/92 vendors)
- **Common hosting pattern:** Cloudflare and AWS used to mask true server location in 3/5 cases

---

## 🚫 Recommended Blocking Actions

1. Add all 5 domains above to email gateway and DNS firewall blocklists
2. Submit IP addresses to threat intel sharing platforms (e.g. AbuseIPDB)
3. Report all URLs to PhishTank community verification queue
4. Monitor for typosquat variants of these 5 brand names (Sahibinden, Carrefour, Apple, Smart Fit, generic medical services)

---

*Compiled from individual case files PHI-001 through PHI-005. See `/cases` folder for full investigation details.*
