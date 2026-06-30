# Phishing Investigation Project

This is a small project where I picked real phishing URLs from PhishTank (a site where people report phishing links) and checked them myself using VirusTotal to see if they were actually malicious.

I did 5 cases total. For each one I found the phishing URL, checked it on VirusTotal to see how many antivirus companies flagged it, found the server IP hosting it, and wrote up what I found.

## Tools I used
- PhishTank - to find real reported phishing URLs
- VirusTotal - to check if URLs/IPs are flagged as malicious by security vendors

## Cases

| Case | Brand they faked | Detection score | Server IP |
|---|---|---|---|
| PHI-001 | Sahibinden | 4/92 | 104.21.20.125 |
| PHI-002 | Carrefour | 1/92 | 13.32.205.46 |
| PHI-003 | Fake medical site | 16/92 | 216.55.149.9 |
| PHI-004 | Apple iCloud | 3/90 | 69.16.230.228 |
| PHI-005 | Smart Fit | 5/92 | 172.67.169.143 |

## What I learned doing this
- new phishing domains often show 0 detections at first because nobody's reported them yet to antivirus companies - doesn't mean they're safe
- attackers host phishing sites on Cloudflare and AWS a lot because it makes them harder to block and look more trustworthy
- domain registration date matters - if a domain was made the same day as the attack, that's a huge red flag
- how to actually use VirusTotal beyond just searching - checking the Details tab for IP info, Relations tab for connected infrastructure

See the /cases folder for the full writeup on each one.
