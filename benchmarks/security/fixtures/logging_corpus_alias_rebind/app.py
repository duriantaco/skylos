import logging
import os
payload = ["request", os.getenv("SERVICE_API_TOKEN")]
alias = payload
alias = ["request", "[REDACTED]"]
logging.info("request: %s", payload)
