import logging
import os
import requests
response = requests.get("https://api.example.test/items",
                        params={"token": os.getenv("SERVICE_API_TOKEN")}, timeout=10)
logging.info("request URL: %s", response.url)
