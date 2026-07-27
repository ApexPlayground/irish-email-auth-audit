QUALIFIER_SCORES = {
    "-all": 4,
    "~all": 3,
    "?all": 2,
    "+all": 1,
}

LOOKUP_LIMIT = 10  # RFC 7208 hard ceiling
LOOKUP_MECHANISMS = ["include:", "a:", "a ", "mx:", "mx ", "ptr:", "ptr ", "exists:", "redirect="]


def get_qualifier(record):
    if record.endswith("-all"):
        return "-all"
    if record.endswith("~all"):
        return "~all"
    if record.endswith("?all"):
        return "?all"
    if record.endswith("+all") or record.endswith(" all"):
        return "+all"
    return None


def count_lookups(record):
    count = 0
    for mech in LOOKUP_MECHANISMS:
        count += record.count(mech)
    return count


def score_spf(record):
    if not record:
        return {
            "qualifier": None,
            "qualifier_score": None,  # unmeasured, not the same as +all
            "lookup_count": 0,
            "lookup_exceeds_limit": False,
        }

    qualifier = get_qualifier(record)
    qualifier_score = QUALIFIER_SCORES.get(qualifier, 1)
    lookups = count_lookups(record)

    return {
        "qualifier": qualifier,
        "qualifier_score": qualifier_score,
        "lookup_count": lookups,
        "lookup_exceeds_limit": lookups > LOOKUP_LIMIT,
    }


if __name__ == "__main__":
    tests = [
        "v=spf1 mx a ip4:137.191.246.12 include:spf.tmes.trendmicro.com ?all",
        "v=spf1 ip4:137.191.252.74 ip4:137.191.252.75 -all",
        "v=spf1 include:_spf.google.com ip4:136.206.1.100 ip4:198.187.196.100 ip4:193.120.143.134 include:spf-eu.exlibrisgroup.com include:spf.protection.outlook.com include:mail.zendesk.com ~all",
        None,
    ]
    for t in tests:
        print(t)
        print(score_spf(t))
        print()