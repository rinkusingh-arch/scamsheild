from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List


@dataclass
class Finding:
    weight: float  # 0..1, how suspicious this signal is on its own
    reason: str


@dataclass
class Report:
    kind: str
    subject: str
    score: int
    level: str
    advice: str
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


_ADVICE = {
    "LOW": "No strong red flags, but still verify the sender or site independently.",
    "MEDIUM": "Some warning signs. Verify through an official channel before proceeding.",
    "HIGH": "Likely a scam. Do not pay, share documents, or scan/click further.",
    "CRITICAL": "Almost certainly a scam. Stop, don't pay or share anything, and report it.",
}


def combine(findings: List[Finding]) -> int:
    """Noisy-OR: independent weak signals add up, but never exceed 100."""
    p_safe = 1.0
    for f in findings:
        p_safe *= 1.0 - min(max(f.weight, 0.0), 0.95)
    return round((1.0 - p_safe) * 100)


def level_for(score: int) -> str:
    if score < 20:
        return "LOW"
    if score < 50:
        return "MEDIUM"
    if score < 75:
        return "HIGH"
    return "CRITICAL"


def build_report(kind: str, subject: str, findings: List[Finding]) -> Report:
    seen, unique = set(), []
    for f in findings:
        if f.reason not in seen:
            seen.add(f.reason)
            unique.append(f)
    unique.sort(key=lambda f: f.weight, reverse=True)
    score = combine(unique)
    level = level_for(score)
    subject = subject if len(subject) <= 200 else subject[:197] + "..."
    return Report(kind, subject, score, level, _ADVICE[level], unique)


def render_text(r: Report) -> str:
    lines = [f"[{r.kind}] {r.subject}", f"Risk: {r.level} ({r.score}/100)", r.advice]
    if r.findings:
        lines.append("Red flags:")
        lines += [f"  - {f.reason} (+{round(f.weight * 100)})" for f in r.findings]
    return "\n".join(lines)
