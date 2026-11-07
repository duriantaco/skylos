import logging
import os
payload = ["request", os.getenv("SERVICE_API_TOKEN")]
alias = payload
alias[1] = "[REDACTED]"
logging.info("request: %s", payload)
