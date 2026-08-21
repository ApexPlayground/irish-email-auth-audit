"""Parse and score DMARC policy records. Scoring follows RFC 7489 section 6.3."""

import re

POLICY_SCORES = {
    "reject": 4,
    "quarantine": 3,
    "none": 2,
}

TAG_PATTERN = re.compile(r"(\w+)=([^;]+)")


def parse_tags(record):
    return {k.strip(): v.strip() for k, v in TAG_PATTERN.findall(record)}


def score_dmarc(record):
    if not record:
        return {
            "policy": None,
            "policy_score": None,
            "subdomain_policy": None,
            "pct": None,
            "reporting_configured": False,
            "forensic_reporting_configured": False,
            "alignment_spf": None,
            "alignment_dkim": None,
        }

    tags = parse_tags(record)
    policy = tags.get("p")
    pct_raw = tags.get("pct", "100")

    # Defaults are what a receiver applies when the tag is absent:
    # sp inherits p, pct is 100, alignment is relaxed.
    return {
        "policy": policy,
        "policy_score": POLICY_SCORES.get(policy),
        "subdomain_policy": tags.get("sp", policy),
        "pct": int(pct_raw) if pct_raw.isdigit() else None,
        "reporting_configured": "rua" in tags,
        "forensic_reporting_configured": "ruf" in tags,
        "alignment_spf": tags.get("aspf", "r"),
        "alignment_dkim": tags.get("adkim", "r"),
    }