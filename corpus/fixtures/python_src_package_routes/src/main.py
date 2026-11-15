from fastapi import FastAPI
from src.api.routes import accounts
application = FastAPI()
application.include_router(accounts.router)
