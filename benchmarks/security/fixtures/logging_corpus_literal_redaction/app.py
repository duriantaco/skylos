import logging
import os
value = os.getenv("SERVICE_API_TOKEN")
value = "[REDACTED]"
logging.info("credential: %s", value)
