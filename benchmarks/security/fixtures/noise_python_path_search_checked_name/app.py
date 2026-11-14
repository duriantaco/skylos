import os
import re

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.delete("/accounts/{name}")
async def delete_account(name: str):
    if not re.search(r"[a-z0-9_-]+", name):
        raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name))
    return {}
