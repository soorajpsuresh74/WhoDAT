import io
import requests
import config
from config import logger

headers = {
    "x-apikey": config.MySecret.VIRUS_TOTAL_KEY
}

def get_analysis_report(analysis_id):
    try:
        response = requests.get(f"{config.MySecret.VT_ANALYSIS_ENDPOINT}/{analysis_id}", headers=headers)

        if response.status_code == 200:
            result = response.json()
            stats = result["data"]["attributes"]["stats"]

            logger.info(f"✅ Analysis Report: {stats}")

            return {
                "status": True,
                "Malicious": stats.get("malicious", 0),
                "Suspicious": stats.get("suspicious", 0),
                "Harmless": stats.get("harmless", 0),
                "Undetected": stats.get("undetected", 0),
            }
        else:
            logger.warning(f"⚠️ Failed to get analysis report: {response.status_code}, {response.text}")
            return {"status": False, "error": f"Failed to fetch report: {response.status_code}"}

    except Exception as e:
        logger.error(f"❌ Error fetching analysis report: {e}")
        return {"status": False, "error": str(e)}

def virus_total_attachment_analysis(attachment: tuple):
    filename, file_data = attachment

    try:
        if not filename:
            filename = "unknown_file"
        if not isinstance(file_data, (bytes, bytearray, io.BytesIO)):
            raise TypeError("Attachment must be a bytes-like object or io.BytesIO")

        logger.info(f"📤 Uploading file: {filename}")
        file_stream = file_data if isinstance(file_data, io.BytesIO) else io.BytesIO(file_data)

        files = {"file": (filename, file_stream)}

        response = requests.post(config.MySecret.VT_FILE_UPLOAD_ENDPOINT, headers=headers, files=files)

        if response.status_code == 200:
            response_data = response.json()
            analysis_id = response_data["data"]["id"]
            logger.info(f"✅ File uploaded successfully. Analysis ID: {analysis_id}")

            report = get_analysis_report(analysis_id)

            return {
                "status": True,
                "file": filename,
                "analysis": report,
                "message": "File uploaded and analysis completed."
            }
        else:
            logger.warning(f"⚠️ Failed to upload {filename}: {response.status_code} - {response.text}")
            return {
                "status": False,
                "file": filename,
                "error": f"Upload failed with status code {response.status_code}",
                "response": response.json()
            }

    except TypeError as e:
        logger.error(f"❌ TypeError: {str(e)}")
        return {"status": False, "file": filename, "error": str(e)}

    except Exception as e:
        logger.error(f"❌ Exception while uploading {filename}: {str(e)}")
        return {"status": False, "file": filename, "error": str(e)}
