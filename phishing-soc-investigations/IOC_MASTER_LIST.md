# IOC List - all 5 cases combined

Quick reference list of everything found across the 5 phishing investigations. 

## Domains
- sahibinden.elektronik-magaza-sepetim.com (PHI-001)
- carrefour.negocie-aqui.com (PHI-002)
- unitedmedicalsolutions.org (PHI-003)
- icloud-unlock-bypass.com (PHI-004)
- smartfitbr.com (PHI-005)

## URLs
- http://sahibinden.elektronik-magaza-sepetim.com/adres
- https://carrefour.negocie-aqui.com/
- https://unitedmedicalsolutions.org
- http://www.icloud-unlock-bypass.com
- https://www.smartfitbr.com/?gad_source=1&gad_campaignid=2392987030

## IPs
- 104.21.20.125 - Cloudflare - PHI-001
- 13.32.205.46 - Amazon AWS - PHI-002
- 216.55.149.9 - Internet Names For Business Inc - PHI-003
- 69.16.230.228 - PHI-004
- 172.67.169.143 - PHI-005

## Notes
PHI-003 had the highest detection score (16/92), so probably the most actively dangerous one of the batch. 3 out of 5 cases used Cloudflare or AWS for hosting - seems like a common pattern attackers use to hide where the actual server is.

If blocking these at a firewall level, block both the domain and the IP since some of these IPs (like the Carrefour one) had other malicious files connecting to them too, not just this one phishing page.
