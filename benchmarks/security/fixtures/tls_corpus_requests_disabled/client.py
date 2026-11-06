import requests

def fetch_status():
    return requests.get('https://api.example.test/status', verify=False)
