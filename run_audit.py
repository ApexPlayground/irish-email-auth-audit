import csv
import time

from dns_query import get_spf_record, get_dmarc_record
from spf import score_spf
from dmarc import score_dmarc

INPUT_FILE = "domains.csv"
OUTPUT_FILE = "results.csv"
DELAY_SECONDS = 0.5

FIELDNAMES = [
    "organization_name", "domain", "sector",
    "spf_status", "spf_record",
    "spf_qualifier", "spf_qualifier_score",
    "spf_lookup_count", "spf_lookup_exceeds_limit",
    "dmarc_status", "dmarc_record",
    "dmarc_policy", "dmarc_policy_score",
    "dmarc_subdomain_policy", "dmarc_pct",
    "dmarc_reporting_configured", "dmarc_forensic_reporting_configured",
    "dmarc_alignment_spf", "dmarc_alignment_dkim",
]


def load_domains(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(2048)
        f.seek(0)
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",\t")
        except csv.Error:
            dialect = csv.excel
        rows = list(csv.DictReader(f, dialect=dialect))

    if rows and "domain" not in rows[0]:
        raise ValueError(f"no 'domain' column found, got: {list(rows[0].keys())}")

    return rows


def main():
    domains = load_domains(INPUT_FILE)
    print(f"Loaded {len(domains)} domains from {INPUT_FILE}")

    results = []
    for i, row in enumerate(domains, start=1):
        domain = row["domain"]
        print(f"[{i}/{len(domains)}] {domain} ...", end=" ")

        spf = get_spf_record(domain)
        dmarc = get_dmarc_record(domain)
        print(f"spf={spf['status']} dmarc={dmarc['status']}")

        spf_scored = score_spf(spf["record"])
        dmarc_scored = score_dmarc(dmarc["record"])

        spf_unmeasured = spf_scored["qualifier_score"] is None  # blank out, don't score as worst-case
        dmarc_unmeasured = dmarc_scored["policy_score"] is None

        results.append({
            "organization_name": row["organization_name"],
            "domain": domain,
            "sector": row["sector"],
            "spf_status": spf["status"],
            "spf_record": spf["record"] or "",
            "spf_qualifier": spf_scored["qualifier"] or "",
            "spf_qualifier_score": "" if spf_unmeasured else spf_scored["qualifier_score"],
            "spf_lookup_count": "" if spf_unmeasured else spf_scored["lookup_count"],
            "spf_lookup_exceeds_limit": "" if spf_unmeasured else spf_scored["lookup_exceeds_limit"],
            "dmarc_status": dmarc["status"],
            "dmarc_record": dmarc["record"] or "",
            "dmarc_policy": dmarc_scored["policy"] or "",
            "dmarc_policy_score": "" if dmarc_unmeasured else dmarc_scored["policy_score"],
            "dmarc_subdomain_policy": "" if dmarc_unmeasured else dmarc_scored["subdomain_policy"],
            "dmarc_pct": "" if dmarc_unmeasured else dmarc_scored["pct"],
            "dmarc_reporting_configured": "" if dmarc_unmeasured else dmarc_scored["reporting_configured"],
            "dmarc_forensic_reporting_configured": "" if dmarc_unmeasured else dmarc_scored["forensic_reporting_configured"],
            "dmarc_alignment_spf": "" if dmarc_unmeasured else dmarc_scored["alignment_spf"],
            "dmarc_alignment_dkim": "" if dmarc_unmeasured else dmarc_scored["alignment_dkim"],
        })

        time.sleep(DELAY_SECONDS)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nDone. Wrote {len(results)} rows to {OUTPUT_FILE}")

    for label, key in [("SPF", "spf_status"), ("DMARC", "dmarc_status")]:
        print(f"\n{label}:")
        statuses = [r[key] for r in results]
        for status in ("found", "not_published", "nxdomain", "timeout", "error"):
            count = statuses.count(status)
            if count:
                print(f"  {status}: {count}")


if __name__ == "__main__":
    main()