import logging
import os
import requests
response = requests.post("https://auth.example.test/login",
                         data={"password": os.getenv("SERVICE_PASSWORD")}, timeout=10)
logging.info("login status: %s", response.status_code)
