from typing import NamedTuple
import time
import requests

DOH_TIMEOUT = 8

DOH_PROVIDERS = [
    ("google", "https://dns.google/resolve", {}),
    ("cloudflare", "https://cloudflare-dns.com/dns-query",
     {"accept": "application/dns-json"}),
]

# There is no way to enumerate the _domainkey namespace, so DKIM records are
# found by trying the defaults of the major providers and common conventions.
SELECTORS = [
    "google", "selector1", "selector2", "k1", "k2", "default",
    "dkim", "mail", "smtp", "s1", "s2", "litesrv", "mailjet",
]


class TxtResult(NamedTuple):
    strings: list
    status: str


def _resolve_txt(query_name):
    for _, url, headers in DOH_PROVIDERS:
        try:
            resp = requests.get(
                url,
                params={"name": query_name, "type": "TXT"},
                headers=headers,
                timeout=DOH_TIMEOUT,
            )
            data = resp.json()
            status = data.get("Status", -1)

            if status == 3:
                return TxtResult([], "nxdomain")
            if status != 0 or "Answer" not in data:
                return TxtResult([], "not_published")

            return TxtResult([a.get("data", "").strip('"') for a in data["Answer"]], "ok")

        except Exception:
            continue

    return TxtResult([], "timeout")


def _get_txt_record(query_name, prefix):
    result = _resolve_txt(query_name)
    if result.status != "ok":
        return {"record": None, "status": result.status}

    for txt in result.strings:
        if txt.lower().startswith(prefix.lower()):
            return {"record": txt, "status": "found"}

    return {"record": None, "status": "not_published"}


def get_spf_record(domain):
    return _get_txt_record(domain, "v=spf1")


def get_dmarc_record(domain):
    return _get_txt_record(f"_dmarc.{domain}", "v=DMARC1")


def get_dkim_record(domain, selectors=None):
    for selector in selectors or SELECTORS:
        result = _resolve_txt(f"{selector}._domainkey.{domain}")

        if result.status == "ok":
            for txt in result.strings:
                if "v=dkim1" in txt.lower() or "p=" in txt.lower():
                    return {"record": txt, "status": "found", "selector": selector}

        elif result.status == "timeout":
            return {"record": None, "status": "timeout", "selector": selector}

        time.sleep(0.1)

    return {"record": None, "status": "not_published", "selector": None}