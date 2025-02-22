import os
import logging
from dotenv import load_dotenv
load_dotenv()

logging.basicConfig(level=logging.INFO)

PROTOCOL = os.getenv('protocol', None)
HOST = os.getenv('host', None)
PORT = int(os.getenv('port', None))

logging.info(f"Starting server with {PROTOCOL}://{HOST}:{PORT}")