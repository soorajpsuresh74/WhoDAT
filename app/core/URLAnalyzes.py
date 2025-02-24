import io
import logging
from pathlib import Path
import requests
import base64
import config

# Setup logger
app_logger = logging.getLogger("app_logger")
app_logger.setLevel(logging.INFO)

# Console handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)

# File handler
file_handler = logging.FileHandler("app.log")
file_handler.setLevel(logging.INFO)

# Formatter
formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
console_handler.setFormatter(formatter)
file_handler.setFormatter(formatter)

# Add handlers to logger
app_logger.addHandler(console_handler)
app_logger.addHandler(file_handler)

# Load VirusTotal API configurations
VT_FILE_UPLOAD_ENDPOINT = config.MySecret.VT_FILE_UPLOAD_ENDPOINT
VT_ANALYSIS_ENDPOINT = config.MySecret.VT_ANALYSIS_ENDPOINT
VT_URL_SCAN_ENDPOINT = config.MySecret.VIRUS_TOTAL_ENDPOINT
VT_IP_SCAN_ENDPOINT = config.MySecret.VIRUS_TOTAL_IP_ENDPOINT

headers = {
    "x-apikey": config.MySecret.VIRUS_TOTAL_KEY
}

app_logger.info(f"VirusTotal Endpoints: "
                f"\n - File Upload: {VT_FILE_UPLOAD_ENDPOINT}"
                f"\n - Analysis: {VT_ANALYSIS_ENDPOINT}"
                f"\n - URL Scan: {VT_URL_SCAN_ENDPOINT}"
                f"\n - IP Scan: {VT_IP_SCAN_ENDPOINT}")


def virus_total_link_analysis(link):
    result = {}
    error_info = {"status": False, "link": link, "error": "Unknown error occurred"}

    try:
        link_id = base64.urlsafe_b64encode(link.encode()).decode().strip("=")
        request_url = f"{VT_URL_SCAN_ENDPOINT}/{link_id}"
        app_logger.info(f"Scanning link: {link} | URL: {request_url}")

        response = requests.get(request_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            scan_info = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})

            result = {
                "status": True,
                "link": link,
                "malicious": scan_info.get('malicious', 0),
                "suspicious": scan_info.get('suspicious', 0),
                "harmless": scan_info.get('harmless', 0),
                "undetected": scan_info.get('undetected', 0),
                "redirects": data.get("data", {}).get("attributes", {}).get("tags", [])
            }

            app_logger.info(f"Scan result for {link}: {result}")
        else:
            error_info = {
                "status": False,
                "link": link,
                "error": f"Error: {response.status_code}",
                "response": response.json() if response.content else None
            }
            app_logger.warning(f"Failed to scan {link}: {error_info}")

    except requests.RequestException as e:
        error_info = {
            "status": False,
            "link": link,
            "error": f"Request failed: {str(e)}"
        }
        app_logger.error(f"RequestException while scanning {link}: {str(e)}")

    except Exception as e:
        error_info = {
            "status": False,
            "link": link,
            "error": f"Unexpected error: {str(e)}"
        }
        app_logger.error(f"Exception while scanning {link}: {str(e)}")

    return result if result else error_info


def get_analysis_report(analysis_id):
    try:
        request_url = f"{VT_ANALYSIS_ENDPOINT}/{analysis_id}"
        app_logger.info(f"Fetching analysis report | URL: {request_url}")

        response = requests.get(request_url, headers=headers)

        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["stats"]

            app_logger.info(f"Analysis Report for {analysis_id}: {stats}")

            return {
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
            }
        else:
            app_logger.warning(f"Failed to get analysis report: {response.status_code}, {response.text}")
            return None

    except Exception as e:
        app_logger.error(f"Error fetching analysis report: {e}")
        return None


def virus_total_attachment_analysis(attachment: tuple):
    filename, file_data = attachment
    result = {}
    error_info = {"status": False, "file_name": filename, "error": "Unknown error occurred"}

    try:
        if not filename:
            filename = "unknown_file"
        if not isinstance(file_data, (bytes, bytearray, io.BytesIO)):
            raise TypeError("Attachment must be a bytes-like object or io.BytesIO")

        request_url = VT_FILE_UPLOAD_ENDPOINT
        app_logger.info(f"Uploading file: {filename} | URL: {request_url}")

        file_stream = file_data if isinstance(file_data, io.BytesIO) else io.BytesIO(file_data)
        files = {"file": (filename, file_stream)}

        response = requests.post(request_url, headers=headers, files=files)

        if response.status_code == 200:
            response_data = response.json()
            analysis_id = response_data["data"]["id"]
            app_logger.info(f"File uploaded successfully. Analysis ID: {analysis_id}")

            report = get_analysis_report(analysis_id)
            result = {
                "status": True,
                "file": filename,
                "analysis": report
            }
        else:
            error_info = {
                "status": False,
                "file": filename,
                "error": f"Error: {response.status_code}",
                "response": response.json()
            }
            app_logger.warning(f"Failed to upload {filename}: {error_info}")

    except TypeError as e:
        app_logger.error(f"TypeError: {str(e)}")
        error_info["error"] = str(e)

    except Exception as e:
        app_logger.error(f"Exception while uploading {filename}: {str(e)}")
        error_info["error"] = str(e)

    return result if result else error_info
