import time
import dns.resolver

QUALIFIER_SCORES = {
    "-all": 4,
    "~all": 3,
    "?all": 2,
    "+all": 1,
}

LOOKUP_LIMIT = 10          # RFC 7208 section 4.6.4
MAX_RECURSION_DEPTH = 10

NAMESERVER_SETS = [
    ["8.8.8.8", "8.8.4.4"],
    ["1.1.1.1", "1.0.0.1"],
]
TIMEOUT = 5
LIFETIME = 8


def get_qualifier(record):
    record = record.lower()
    for qualifier in ("-all", "~all", "?all", "+all"):
        if record.endswith(qualifier):
            return qualifier
    if record.endswith(" all"):
        return "+all"        # a bare "all" defaults to the pass qualifier
    return None


def _resolve_spf_txt(domain):
    for nameservers in NAMESERVER_SETS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = nameservers
        resolver.timeout = TIMEOUT
        resolver.lifetime = LIFETIME
        try:
            for rdata in resolver.resolve(domain, "TXT"):
                txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
                if txt.lower().startswith("v=spf1"):
                    return txt
            return None
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            return None
        except Exception:
            continue
    return None


def _extract_lookup_targets(record):
    """Return (mechanism, target) for each term costing a DNS lookup.

    target is None for mechanisms that do not reference another SPF record.
    """
    targets = []
    for token in record.split():
        low = token.lower()
        if low.startswith("include:"):
            targets.append(("include", token.split(":", 1)[1]))
        elif low.startswith("redirect="):
            targets.append(("redirect", token.split("=", 1)[1]))
        elif low == "a" or low.startswith(("a:", "a/")):
            targets.append(("a", None))
        elif low == "mx" or low.startswith(("mx:", "mx/")):
            targets.append(("mx", None))
        elif low.startswith("ptr"):
            targets.append(("ptr", None))
        elif low.startswith("exists:"):
            targets.append(("exists", None))
    return targets


def count_lookups(record, visited=None, depth=0):
    """Count DNS-querying terms across the whole evaluation.

    The RFC 7208 limit covers lookups nested inside include and redirect
    targets, so the full chain has to be expanded rather than just the
    published record.
    """
    if visited is None:
        visited = set()
    if depth > MAX_RECURSION_DEPTH:
        return LOOKUP_LIMIT + 1

    total = 0
    for mech, target in _extract_lookup_targets(record):
        total += 1
        if total > LOOKUP_LIMIT:
            return total

        if mech in ("include", "redirect") and target:
            key = target.lower()
            if key in visited:
                continue        # circular include
            visited.add(key)

            sub_record = _resolve_spf_txt(target)
            if sub_record:
                total += count_lookups(sub_record, visited, depth + 1)
                if total > LOOKUP_LIMIT:
                    return total
            time.sleep(0.1)

    return total


def score_spf(record):
    if not record:
        return {
            "qualifier": None,
            "qualifier_score": None,
            "lookup_count": 0,
            "lookup_exceeds_limit": False,
        }

    qualifier = get_qualifier(record)
    lookups = count_lookups(record)

    return {
        "qualifier": qualifier,
        "qualifier_score": QUALIFIER_SCORES.get(qualifier, 2),
        "lookup_count": lookups,
        "lookup_exceeds_limit": lookups > LOOKUP_LIMIT,
    }