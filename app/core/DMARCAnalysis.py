import dns.resolver

def fetch_dmarc_record(domain: str) -> dict:
    """Fetch and parse the DMARC record of a domain."""
    dmarc_record = {}
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
        for record in txt_records:
            dmarc_text = record.to_text().strip('"')
            if dmarc_text.startswith("v=DMARC1"):
                dmarc_record["raw"] = dmarc_text
                for tag in dmarc_text.split(";"):
                    key_value = tag.strip().split("=")
                    if len(key_value) == 2:
                        dmarc_record[key_value[0]] = key_value[1]
                return dmarc_record
        return {"error": "No valid DMARC record found"}
    except Exception as e:
        return {"error": f"DMARC lookup failed: {e}"}
