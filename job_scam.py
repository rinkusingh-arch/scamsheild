from __future__ import annotations

import re
from typing import List

from .scoring import Finding, Report, build_report
from .url_analysis import analyze_url

FREE_MAIL = {"gmail.com", "yahoo.com", "yahoo.in", "outlook.com", "hotmail.com", "proton.me",
             "protonmail.com", "rediffmail.com", "aol.com", "mail.com", "icloud.com"}

RULES = [
    (r"(registration|training|processing|application|admin|security|verification|onboarding|kit|laptop|uniform|background[- ]check)\s+(fee|deposit|charges?|payment)",
     0.55, "Asks for an upfront fee or deposit"),
    (r"\b(pay|send|transfer|deposit)\b[^.\n]{0,40}\b(to (secure|confirm|reserve|book|hold)|before (you )?(start|join|onboard))",
     0.45, "Asks you to pay before starting"),
    (r"(fully )?refundable (fee|deposit|amount)", 0.2, "Promises a 'refundable' fee"),
    (r"\b(send|mail|deposit)\b[^.\n]{0,40}\b(cheque|check)\b|\b(cheque|check)\b[^.\n]{0,60}(purchase|buy|vendor|equipment)",
     0.5, "Check/overpayment scheme pattern"),
    (r"(buy|purchase|order)[^.\n]{0,30}(equipment|laptop|software|supplies)[^.\n]{0,40}(reimburs|refund|vendor|our (approved )?supplier)",
     0.45, "Asks you to buy equipment and be reimbursed later"),
    (r"\b(aadhaar|aadhar|pan card|ssn|social security|passport (copy|scan|number)|bank (account|details|login)|net ?banking|card number|cvv|otp)\b",
     0.4, "Requests sensitive ID/financial info before a real hiring process"),
    (r"\b(whatsapp|telegram|signal)\b", 0.25, "Moves the conversation to WhatsApp/Telegram"),
    (r"(interview|chat|screening)[^.\n]{0,40}\b(on|via|through|over)\s+(telegram|whatsapp|google hangouts|signal|text)",
     0.35, "Interview conducted only over a chat app"),
    (r"(hired|selected|shortlisted|offer)[^.\n]{0,30}(without|no)\s+(an?\s+)?interview|you('| a)re (already )?(selected|hired)",
     0.35, "Job offered without a real interview"),
    (r"(earn|make|income)[^.\n]{0,25}(\$|₹|rs\.?|usd|inr)\s?\d[\d,]*\s*(/|per|a)\s*(day|daily|hour|hr|week)",
     0.35, "Unrealistic pay for the work described"),
    (r"\b(guaranteed|assured)\b[^.\n]{0,20}(income|salary|earnings|job|placement)", 0.3, "Guaranteed income/job claim"),
    (r"(like|subscribe|rate|review|boost|click)\b[^.\n]{0,30}(videos?|products?|apps?|ads?|links?|hotels?)[^.\n]{0,40}(earn|commission|reward|paid)|(complete|finish)\s+(daily\s+)?(simple\s+)?tasks?",
     0.45, "Task/commission scam pattern (likes, ratings, simple tasks)"),
    (r"\b(data entry|typing job|form filling|copy[- ]paste)\b[^.\n]{0,40}(earn|income|salary|₹|\$)", 0.25, "Too-easy 'data entry' work with high pay"),
    (r"no (experience|skills?|qualifications?)( (is )?(needed|required))?", 0.15, "'No experience needed' bait"),
    (r"(work|earn) from (home|anywhere)[^.\n]{0,60}(part[- ]time|simple|easy)|easy (work|money|job)", 0.2, "'Easy money' work-from-home pitch"),
    (r"\b(crypto|bitcoin|usdt|btc|gift cards?|itunes card|wire transfer|western union)\b", 0.35, "Payment via crypto, gift cards or wire transfer"),
    (r"(urgent(ly)?|immediate(ly)? joining|limited (slots|seats|vacanc)|act now|apply (today|now) only|offer expires)", 0.15, "Pressure / urgency tactics"),
    (r"dear (candidate|applicant|sir/madam|job seeker)", 0.1, "Generic greeting"),
    (r"(we (found|saw)|your) (your )?(resume|cv|profile)[^.\n]{0,40}(shortlist|select|match|perfect)", 0.1, "Unsolicited 'your profile was shortlisted' message"),
]
_COMPILED = [(re.compile(p, re.I), w, why) for p, w, why in RULES]
_URL = re.compile(r"(?:https?://|www\.)[^\s<>\"')]+|\b(?:bit\.ly|tinyurl\.com|t\.me|wa\.me|cutt\.ly|rb\.gy)/\S+", re.I)
_EMAIL = re.compile(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)")


def analyze_job_text(text: str) -> Report:
    findings: List[Finding] = []
    for rx, weight, reason in _COMPILED:
        if rx.search(text):
            findings.append(Finding(weight, reason))

    for m in _URL.finditer(text):
        link = m.group(0).rstrip(".,;")
        for f in analyze_url(link):
            findings.append(Finding(f.weight, f"Link {link[:50]}: {f.reason}"))

    for m in _EMAIL.finditer(text):
        domain = m.group(1).lower()
        if domain in FREE_MAIL:
            findings.append(Finding(0.25, f"Recruiter uses a free email address (@{domain})"))
        else:
            for f in analyze_url(domain):
                findings.append(Finding(f.weight, f"Email domain {domain}: {f.reason}"))

    return build_report("job-offer", text.strip().replace("\n", " "), findings)
