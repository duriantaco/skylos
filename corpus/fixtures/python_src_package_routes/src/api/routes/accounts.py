from fastapi import APIRouter

router = APIRouter(prefix="/api/accounts")


@router.get("")
async def list_accounts():
    return []


@router.post("/x")
async def create_account():
    return 1


@router.websocket("/ws")
async def account_socket(websocket):
    await websocket.accept()


def orphan_helper():
    return 2
