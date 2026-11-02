from __future__ import annotations

from .model import FAIL, WARN, Check

GRADES = ("A+", "A", "B", "C", "D", "F")
THRESHOLDS = ((90, "A"), (80, "B"), (70, "C"), (60, "D"))


def score(checks: list[Check]) -> int:
    return max(0, 100 - sum(c.penalty for c in checks))


def grade(checks: list[Check]) -> str:
    by_id = {c.id: c for c in checks}
    # A domain with neither a usable SPF policy nor DMARC enforcement is trivially spoofable: cap at F.
    spf_blocks = by_id.get("spf-policy") and by_id["spf-policy"].status == "pass"
    dmarc_enforces = by_id.get("dmarc-policy") and by_id["dmarc-policy"].status in ("pass", "warn")
    if not spf_blocks and not dmarc_enforces:
        return "F"
    points = score(checks)
    # A+ is a clean sheet: no failures and no warnings, not merely a high score.
    if points >= 95 and not any(c.status in (FAIL, WARN) for c in checks):
        return "A+"
    for threshold, letter in THRESHOLDS:
        if points >= threshold:
            return letter
    return "F"


def at_least(letter: str, minimum: str) -> bool:
    return GRADES.index(letter) <= GRADES.index(minimum)
