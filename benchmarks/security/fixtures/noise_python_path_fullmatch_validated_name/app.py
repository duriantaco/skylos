import os
import re

from fastapi import APIRouter, HTTPException

router = APIRouter()
NAME_RE = re.compile(r"^[a-zA-Z0-9_-]{1,50}$")


def _validate_name(name: str) -> str:
    trimmed = name.strip()
    if not trimmed or not NAME_RE.match(trimmed):
        raise HTTPException(status_code=400, detail="bad name")
    return trimmed


@router.delete("/accounts/{name}")
async def delete_account(name: str):
    account = _validate_name(name)
    os.remove(os.path.join("state", f"{account}.json"))
    return {"deleted": account}
