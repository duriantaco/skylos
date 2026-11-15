from fastapi import APIRouter

router = APIRouter(prefix="/api/stale")


@router.get("")
async def never_mounted_route():
    return []
