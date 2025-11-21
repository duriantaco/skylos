from fastapi import FastAPI, APIRouter, Depends
from pydantic import BaseModel, field_validator
from typing import Any  # unused

app = FastAPI()
router = APIRouter()


class In(BaseModel):
    x: int

    @field_validator("x")
    @classmethod
    def nonneg(cls, v):
        assert v >= 0
        return v


class Out(BaseModel):
    y: int


# dead
class UnusedModel(BaseModel):
    z: int


# dead
def dep():
    return "dep"


# dead
def unused_helper():
    return 123


# used
@router.get("/ping")
def ping():
    return {"ok": True}


@router.post("/calc")
def calc(req):
    return {"y": req.x + 1}


app.include_router(router)
