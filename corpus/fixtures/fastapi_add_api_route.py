from fastapi import FastAPI

app = FastAPI()


async def read_items():
    return []


app.add_api_route("/items", read_items, methods=["GET"])
