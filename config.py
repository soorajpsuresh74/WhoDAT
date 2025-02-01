import os
from WhoDATLogger import setup_logger
from dotenv import load_dotenv

load_dotenv()
logger = setup_logger("MySecretLogger")

class MySecret:
    VIRUS_TOTAL_KEY = os.getenv("VIRUS_TOTAL_KEY", 'Key not obtained')
    logger.info(f"VIRUS_TOTAL_KEY: {'Obtained' if VIRUS_TOTAL_KEY != 'Key not obtained' else 'Not obtained'}")
    VIRUS_TOTAL_ENDPOINT = os.getenv("VIRUS_TOTAL_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_ENDPOINT: {'Obtained' if VIRUS_TOTAL_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    VT_FILE_UPLOAD_ENDPOINT = os.getenv("VT_FILE_UPLOAD_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_KEY: {'Obtained' if VT_FILE_UPLOAD_ENDPOINT != 'Key not obtained' else 'Not obtained'}")
    VT_ANALYSIS_ENDPOINT = os.getenv("VT_ANALYSIS_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_KEY: {'Obtained' if VT_ANALYSIS_ENDPOINT != 'Key not obtained' else 'Not obtained'}")
    VT_IP_SCAN_ENDPOINT = os.getenv("VT_IP_SCAN_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_KEY: {'Obtained' if VT_IP_SCAN_ENDPOINT != 'Key not obtained' else 'Not obtained'}")
