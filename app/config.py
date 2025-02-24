import os
import logging
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Logger Setup
def setup_logger(name="app_logger", level=logging.INFO):
    logger = logging.getLogger(name)
    logger.setLevel(level)

    # Console Handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)

    # Formatter
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)

    # Add Handler if Not Already Added
    if not logger.handlers:
        logger.addHandler(console_handler)

    return logger

# Initialize Logger
logger = setup_logger()

# Read environment variables
PROTOCOL = os.getenv('protocol', None)
HOST = os.getenv('host', None)
PORT = os.getenv('port', None)

if PORT:
    PORT = int(PORT)  # Convert to integer if it's not None

logger.info(f"Starting server with {PROTOCOL}://{HOST}:{PORT}")

class MySecret:
    logger.info("Initializing MySecret class...")

    VIRUS_TOTAL_KEY = os.getenv("VIRUS_TOTAL_KEY", 'Key not obtained')
    logger.info(f"VIRUS_TOTAL_KEY: {'Obtained' if VIRUS_TOTAL_KEY != 'Key not obtained' else 'Not obtained'}")

    VIRUS_TOTAL_ENDPOINT = os.getenv("VIRUS_TOTAL_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_ENDPOINT: {'Obtained' if VIRUS_TOTAL_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    VT_FILE_UPLOAD_ENDPOINT = os.getenv("VT_FILE_UPLOAD_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VT_FILE_UPLOAD_ENDPOINT: {'Obtained' if VT_FILE_UPLOAD_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    VT_ANALYSIS_ENDPOINT = os.getenv("VT_ANALYSIS_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VT_ANALYSIS_ENDPOINT: {'Obtained' if VT_ANALYSIS_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    VT_IP_SCAN_ENDPOINT = os.getenv("VT_IP_SCAN_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VT_IP_SCAN_ENDPOINT: {'Obtained' if VT_IP_SCAN_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    URLSCANIO_API_KEY = os.getenv("URLSCANIO_API_KEY", 'Key not obtained')
    logger.info(f"URLSCANIO_API_KEY: {'Obtained' if URLSCANIO_API_KEY != 'Key not obtained' else 'Not obtained'}")

    URLSCANIO_ENDPOINT = os.getenv("URLSCANIO_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"URLSCANIO_ENDPOINT: {'Obtained' if URLSCANIO_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

    VIRUS_TOTAL_IP_ENDPOINT = os.getenv("VIRUS_TOTAL_IP_ENDPOINT", 'Endpoint not obtained')
    logger.info(f"VIRUS_TOTAL_IP_ENDPOINT: {'Obtained' if VIRUS_TOTAL_IP_ENDPOINT != 'Endpoint not obtained' else 'Not obtained'}")

logger.info("Configuration loaded successfully.")
