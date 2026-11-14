import os
import re

from fastapi import APIRouter, HTTPException

router = APIRouter()
PREFIX_RE = re.compile(r"[a-zA-Z0-9_-]+")


@router.delete("/accounts/{name}")
async def delete_account(name: str):
    if not PREFIX_RE.match(name):
        raise HTTPException(status_code=400)
    os.remove(os.path.join("state", name))
    return {}
