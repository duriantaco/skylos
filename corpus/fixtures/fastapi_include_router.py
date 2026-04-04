from fastapi import APIRouter, FastAPI

app = FastAPI()
router = APIRouter()


@router.get("/ping")
def ping():
    return {"ok": True}


app.include_router(router)
