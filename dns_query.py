from typing import NamedTuple
import time
import dns.resolver

NAMESERVER_SETS = [
    ["8.8.8.8", "8.8.4.4"],
    ["1.1.1.1", "1.0.0.1"],
]

MAX_RETRIES = 1
RETRY_DELAY = 1
TIMEOUT = 4
LIFETIME = 6


class TxtResult(NamedTuple):
    answers: object
    status: str


def _make_resolver(nameservers):
    r = dns.resolver.Resolver()
    r.nameservers = nameservers
    r.timeout = TIMEOUT
    r.lifetime = LIFETIME
    return r


def _resolve_txt(query_name):
    # tries each resolver set in turn before giving up as "timeout"
    for nameservers in NAMESERVER_SETS:
        resolver = _make_resolver(nameservers)
        for attempt in range(MAX_RETRIES + 1):
            try:
                answers = resolver.resolve(query_name, "TXT")
                return TxtResult(answers, "ok")
            except dns.resolver.NXDOMAIN:
                return TxtResult(None, "nxdomain")
            except dns.resolver.NoAnswer:
                return TxtResult(None, "not_published")
            except (dns.exception.Timeout, dns.resolver.NoNameservers):
                if attempt < MAX_RETRIES:
                    time.sleep(RETRY_DELAY * (attempt + 1))
                    continue
                break
            except Exception:
                return TxtResult(None, "error")
    return TxtResult(None, "timeout")


def _get_txt_record(query_name, prefix):
    result = _resolve_txt(query_name)

    if result.status in ("nxdomain", "not_published", "timeout", "error"):
        return {"record": None, "status": result.status}

    for rdata in result.answers:
        txt = b"".join(rdata.strings).decode("utf-8", errors="ignore")
        if txt.startswith(prefix):
            return {"record": txt, "status": "found"}

    return {"record": None, "status": "not_published"}


def get_spf_record(domain):
    return _get_txt_record(domain, "v=spf1")


def get_dmarc_record(domain):
    # DMARC lives at _dmarc.<domain>, not the apex
    return _get_txt_record(f"_dmarc.{domain}", "v=DMARC1")


if __name__ == "__main__":
    for d in ["welfare.ie", "dcu.ie", "hse.ie"]:
        r = get_spf_record(d)
        print(f"SPF   {d}: [{r['status']}] {r['record']}")
        r = get_dmarc_record(d)
        print(f"DMARC {d}: [{r['status']}] {r['record']}")