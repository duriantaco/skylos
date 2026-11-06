import logging
import os
logger = logging.getLogger(__name__)
value = os.getenv("SERVICE_API_TOKEN")
logger.warning("credential: %s", value)
