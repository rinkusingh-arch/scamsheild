# ScamShield 🛡️

Detect **job-offer scams** ("jobtraps") and **fake / malicious QR codes** using transparent, rule-based heuristics.
No API keys, no data leaves your machine, and every verdict lists the exact red flags that triggered it.

## What it catches

**Job scams**
- Upfront "registration / training / security" fees and refundable-deposit tricks
- Fake-check and "buy equipment, we'll reimburse you" schemes
- Requests for Aadhaar/PAN/SSN/bank details/OTP before a real hiring process
- Telegram/WhatsApp-only interviews, "selected without interview", like-and-earn task scams
- Unrealistic pay, crypto/gift-card payments, urgency pressure
- Free-mail recruiters, look-alike company domains, shortened or suspicious links in the message

**QR codes** (decoded from an image or a payload string)
- URL checks: shorteners, raw IPs, punycode/look-alike characters, `user@` tricks, typosquatted brands
  (e.g. `paypa1.com`), brand-in-subdomain tricks, suspicious TLDs, open redirects, http-only
- UPI `collect` requests (approving one *sends* money), pre-filled amounts
- Pre-filled SMS / phone / crypto payment / open Wi-Fi QR payloads

## Install

```bash
pip install -e ".[qr]"        # CLI + QR image decoding
pip install -e ".[qr,web]"    # add the web UI
```

## Use

```bash
scamshield job --file examples/fake_job.txt
scamshield job --text "Pay a refundable registration fee to secure your seat"
scamshield qr photo_of_qr.png
scamshield qr --payload "upi://collect?pa=x@upi&am=5000"
scamshield url http://paypa1.com/login
scamshield qr photo.png --json      # for scripts
python app.py                       # web UI at http://127.0.0.1:5000
```

Exit code is `1` when the risk score is ≥ 50, so you can use it in scripts.

## Limits (please read)

- This is a heuristic scorer, not a guarantee. It can miss scams and occasionally flag legitimate items.
- It cannot detect a **sticker pasted over a real QR code**; physically check that the code hasn't been tampered with.
- It doesn't look up live reputation data. Combine it with Google Safe Browsing / VirusTotal for extra confidence.
- Never pay to get a job. Verify recruiters through the company's official careers site.

## Develop

```bash
pip install -e ".[dev,qr]" && pytest
```
Add or tune rules in `scamshield/job_scam.py` (`RULES`) and `scamshield/url_analysis.py`. PRs welcome.

## License
MIT
