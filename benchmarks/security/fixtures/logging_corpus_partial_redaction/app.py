import logging
import os
value = os.getenv("SERVICE_API_TOKEN")
if input("redact? ") == "yes":
    value = "[REDACTED]"
logging.info("credential: %s", value)
