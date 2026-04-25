import httpx
from fastapi import FastAPI, Request


app = FastAPI()


@app.get("/mirror")
async def mirror_url(request: Request):
    url = request.query_params.get("url")
    return httpx.get(url).text


@app.get("/status")
async def fetch_status():
    return httpx.get("https://status.internal.local/health").text
