import requests

import config

VT_IP_SCAN_ENDPOINT = config.MySecret.VT_IP_SCAN_ENDPOINT
headers = {"x-apikey": config.MySecret.VIRUS_TOTAL_KEY}

def ip_addresses_analysis(ip_addresses):
    results = []

    for ip in ip_addresses:
        try:
            response = requests.get(f"{VT_IP_SCAN_ENDPOINT}/{ip}", headers=headers)

            if response.status_code == 200:
                data = response.json()
                analysis_stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                result = {
                    "ip": ip,
                    "malicious": analysis_stats.get('malicious', 0),
                    "suspicious": analysis_stats.get('suspicious', 0),
                    "harmless": analysis_stats.get('harmless', 0),
                    "undetected": analysis_stats.get('undetected', 0),
                }
            else:
                result = {"ip": ip, "error": f"Failed to fetch data: {response.status_code}"}

        except Exception as e:
            result = {"ip": ip, "error": f"Exception occurred: {str(e)}"}

        results.append(result)

    return results

