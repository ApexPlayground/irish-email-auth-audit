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
            "policy_score": None,  # unmeasured, not the same as p=none
            "subdomain_policy": None,
            "pct": None,
            "reporting_configured": False,
            "forensic_reporting_configured": False,
            "alignment_spf": None,
            "alignment_dkim": None,
        }

    tags = parse_tags(record)

    policy = tags.get("p")
    policy_score = POLICY_SCORES.get(policy)
    subdomain_policy = tags.get("sp", policy)  # sp= inherits p= when absent

    pct_raw = tags.get("pct", "100")
    pct = int(pct_raw) if pct_raw.isdigit() else None

    alignment_spf = tags.get("aspf", "r")
    alignment_dkim = tags.get("adkim", "r")

    return {
        "policy": policy,
        "policy_score": policy_score,
        "subdomain_policy": subdomain_policy,
        "pct": pct,
        "reporting_configured": "rua" in tags,
        "forensic_reporting_configured": "ruf" in tags,
        "alignment_spf": alignment_spf,
        "alignment_dkim": alignment_dkim,
    }


if __name__ == "__main__":
    tests = [
        "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc@example.gov.ie",
        "v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:a@x.ie; ruf=mailto:b@x.ie; aspf=s; adkim=s",
        "v=DMARC1; p=none",
        None,
    ]
    for t in tests:
        print(t)
        print(score_dmarc(t))
        print()