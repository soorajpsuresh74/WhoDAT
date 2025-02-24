import logging

try:
    import config_v1
    HOST = config_v1.HOST
    PORT = config_v1.PORT
    PROTOCOL = config_v1.PROTOCOL
except ImportError:
    logging.warning("config file not found, using default values.")
    HOST = "127.0.0.1"
    PORT = 8000
    PROTOCOL = "http"
