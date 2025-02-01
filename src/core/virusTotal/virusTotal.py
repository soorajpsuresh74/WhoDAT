import requests
import base64
import config
from WhoDATLogger import setup_logger

logger = setup_logger("VirusTotalLogger")

VT_FILE_UPLOAD_ENDPOINT = "https://www.virustotal.com/api/v3/files"
VT_ANALYSIS_ENDPOINT = "https://www.virustotal.com/api/v3/analyses"
VT_URL_SCAN_ENDPOINT = config.MySecret.VIRUS_TOTAL_ENDPOINT

headers = {
    "x-apikey": config.MySecret.VIRUS_TOTAL_KEY
}


def virus_total(links):
    results = []

    for link in links:
        try:
            link_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
            logger.info(f"Scanning link: {link}")

            response = requests.get(f"{VT_URL_SCAN_ENDPOINT}/{link_id}", headers=headers)

            if response.status_code == 200:
                data = response.json()
                scan_info = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

                result = {
                    "link": link,
                    "malicious": scan_info.get('malicious', 0),
                    "suspicious": scan_info.get('suspicious', 0),
                    "harmless": scan_info.get('harmless', 0),
                    "undetected": scan_info.get('undetected', 0)
                }

                logger.info(f"Scan result for {link}: {result}")
                results.append(result)
            else:
                error_info = {
                    "link": link,
                    "error": f"Error: {response.status_code}",
                    "response": response.json()
                }
                logger.warning(f"Failed to scan {link}: {error_info}")
                results.append(error_info)

        except Exception as e:
            logger.error(f"Exception occurred while scanning {link}: {str(e)}")

    return results


def get_analysis_report(analysis_id):
    try:
        response = requests.get(f"{VT_ANALYSIS_ENDPOINT}/{analysis_id}", headers=headers)

        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["stats"]

            logger.info(f"Analysis Report: {stats}")

            return {
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
            }
        else:
            logger.warning(f"Failed to get analysis report: {response.status_code}, {response.text}")
            return None

    except Exception as e:
        logger.error(f"Error fetching analysis report: {e}")
        return None


def virus_total_attachments(attachments):
    results = []

    for attachment in attachments:
        try:
            if isinstance(attachment, str):
                with open(attachment, "rb") as file_obj:
                    filename = attachment.split("/")[-1]
                    files = {"file": (filename, file_obj.read())}
            else:
                filename = attachment.name
                files = {"file": (filename, attachment.getvalue())}

            logger.info(f"Uploading file: {filename}")

            response = requests.post(VT_FILE_UPLOAD_ENDPOINT, headers=headers, files=files)

            if response.status_code == 200:
                response_data = response.json()
                analysis_id = response_data["data"]["id"]
                logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")

                result = get_analysis_report(analysis_id)
                results.append({
                    "file": filename,
                    "analysis": result
                })
            else:
                error_info = {
                    "file": filename,
                    "error": f"Error: {response.status_code}",
                    "response": response.json()
                }
                logger.warning(f"Failed to upload {filename}: {error_info}")
                results.append(error_info)

        except Exception as e:
            logger.error(f"Exception occurred while uploading {filename}: {str(e)}")

    return results