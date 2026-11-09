import logging
import os
def redact(value):
    return value
logging.info("credential: %s", redact(os.getenv("SERVICE_API_TOKEN")))
