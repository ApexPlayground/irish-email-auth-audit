import csv
import time

from dns_query import get_spf_record, get_dmarc_record, get_dkim_record
from spf import score_spf
from dmarc import score_dmarc
from dkim import score_dkim

INPUT_FILE = "domains.csv"
OUTPUT_FILE = "results.csv"
DELAY_SECONDS = 0.5  # avoid hammering DNS servers

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

    "dkim_status", "dkim_selector", "dkim_record",
    "dkim_key_type", "dkim_key_bits", "dkim_key_length_score",
    "dkim_revoked", "dkim_testing_mode",
]


def load_domains(path):
    # excel/sheets exports sometimes come out tab-delimited even with a .csv extension
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


def audit(row):
    domain = row["domain"]

    spf = get_spf_record(domain)
    dmarc = get_dmarc_record(domain)
    dkim = get_dkim_record(domain)

    print(f"spf={spf['status']} dmarc={dmarc['status']} dkim={dkim['status']}")

    result = {
        "organization_name": row["organization_name"],
        "domain": domain,
        "sector": row["sector"],
        "spf_status": spf["status"],
        "spf_record": spf["record"],
        "dmarc_status": dmarc["status"],
        "dmarc_record": dmarc["record"],
        "dkim_status": dkim["status"],
        "dkim_selector": dkim["selector"],
        "dkim_record": dkim["record"],
    }

    # each scorer returns unprefixed keys, so prefix them to match FIELDNAMES
    for prefix, scored in (("spf", score_spf(spf["record"])),
                           ("dmarc", score_dmarc(dmarc["record"])),
                           ("dkim", score_dkim(dkim["record"]))):
        result.update({f"{prefix}_{k}": v for k, v in scored.items()})

    return result


def main():
    domains = load_domains(INPUT_FILE)
    print(f"Loaded {len(domains)} domains from {INPUT_FILE}")

    results = []
    for i, row in enumerate(domains, start=1):
        print(f"[{i}/{len(domains)}] {row['domain']} ...", end=" ")
        results.append(audit(row))
        time.sleep(DELAY_SECONDS)

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(results)

    print(f"\nDone. Wrote {len(results)} rows to {OUTPUT_FILE}")

    for label, key in (("SPF", "spf_status"), ("DMARC", "dmarc_status"), ("DKIM", "dkim_status")):
        statuses = [r[key] for r in results]
        print(f"\n{label} status breakdown:")
        for status in ("found", "not_published", "nxdomain", "timeout", "error"):
            if statuses.count(status):
                print(f"  {status}: {statuses.count(status)}")


if __name__ == "__main__":
    main()