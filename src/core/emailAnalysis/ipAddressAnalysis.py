import requests
import dns.resolver
import config

# Configuration
VT_IP_SCAN_ENDPOINT = config.MySecret.VT_IP_SCAN_ENDPOINT
VT_HEADERS = {"x-apikey": config.MySecret.VIRUS_TOTAL_KEY}
IPINFO_API = "https://ipinfo.io/"
ALLOWED_COUNTRY = "US"  # Change this as needed


def get_ip_geo_info(ip):
    """Fetch geographic and ISP information for an IP address."""
    try:
        response = requests.get(f"{IPINFO_API}{ip}/json")
        if response.status_code == 200:
            data = response.json()
            return {
                "ip": ip,
                "city": data.get("city", "Unknown"),
                "region": data.get("region", "Unknown"),
                "country": data.get("country", "Unknown"),
                "isp": data.get("org", "Unknown"),
                "flagged": data.get("country") != ALLOWED_COUNTRY
            }
        return {"ip": ip, "error": f"Geolocation failed: HTTP {response.status_code}"}
    except requests.RequestException as e:
        return {"ip": ip, "error": f"Geolocation exception: {str(e)}"}


def check_spf_dkim_dmarc(domain):
    """Check SPF, DKIM, and DMARC records for a domain."""
    results = {"SPF": "Not Found", "DKIM": "Not Found", "DMARC": "Not Found"}

    try:
        # 🔹 Check SPF Record
        try:
            spf_records = dns.resolver.resolve(domain, "TXT")
            for record in spf_records:
                txt_value = record.to_text()
                if "v=spf1" in txt_value:
                    results["SPF"] = txt_value
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["SPF"] = "No SPF record found"

        # 🔹 Check DKIM Record
        try:
            dkim_records = dns.resolver.resolve(f"default._domainkey.{domain}", "TXT")
            for record in dkim_records:
                results["DKIM"] = record.to_text()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["DKIM"] = "No DKIM record found"

        # 🔹 Check DMARC Record
        try:
            dmarc_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in dmarc_records:
                results["DMARC"] = record.to_text()
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            results["DMARC"] = "No DMARC record found"

    except Exception as e:
        results["error"] = str(e)

    return results


def ip_addresses_analysis(ip_addresses):
    """Analyzes IP addresses for security threats, origin, and authentication records."""
    results = []

    for ip in ip_addresses:
        try:
            # 🛡 VirusTotal IP Scan
            vt_response = requests.get(f"{VT_IP_SCAN_ENDPOINT}/{ip}", headers=VT_HEADERS)
            vt_data = vt_response.json() if vt_response.status_code == 200 else {}

            analysis_stats = vt_data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            # 🌍 Geolocation & ISP Info
            geo_info = get_ip_geo_info(ip)

            result = {
                "ip": ip,
                "malicious": analysis_stats.get('malicious', 0),
                "suspicious": analysis_stats.get('suspicious', 0),
                "harmless": analysis_stats.get('harmless', 0),
                "undetected": analysis_stats.get('undetected', 0),
                "city": geo_info.get("city"),
                "region": geo_info.get("region"),
                "country": geo_info.get("country"),
                "isp": geo_info.get("isp"),
                "flagged": geo_info.get("flagged"),
            }
        except Exception as e:
            result = {"ip": ip, "error": f"Exception: {str(e)}"}

        results.append(result)

    return results
