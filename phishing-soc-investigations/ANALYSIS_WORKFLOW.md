# How I did this

Just notes for myself on the process I used for each case, in case I do more later.

## Step 1 - find a sample
Go to phishtank.org, browse the list, pick one that's faking a real brand. Copy the URL, don't click it.

## Step 2 - check VirusTotal
Go to virustotal.com, paste URL in the URL tab, hit enter. Look at how many vendors flag it - if it's 0, the domain is probably just too new to be flagged yet, doesn't mean it's safe.

## Step 3 - get the IP
Click Details tab, find "Serving IP Address". That's the server hosting the phishing site.

## Step 4 - check the IP too
Click on the IP, see if it's flagged, see who owns it (Cloudflare, AWS, etc are common since attackers use them to hide).

## Step 5 - write it up
Note down: what brand is being faked, the URL, the IP, the detection score, what I think should be done about it (block domain, report it, etc).

## Things I noticed across all 5 cases
- new domains = mostly 0 detections at first, that's normal not a sign it's safe
- a lot of phishing sites are hosted on big trusted cloud providers (Cloudflare, AWS) on purpose
- domain registered same day as the attack = huge red flag
- detection score isn't the only thing that matters - even a "low" score like 1/92 is still confirmed malicious by at least one source
