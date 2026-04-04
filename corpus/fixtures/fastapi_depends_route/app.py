from fastapi import Depends, FastAPI

app = FastAPI()


def get_db():
    return object()


@app.get("/")
def read_root(db=Depends(get_db)):
    return {"ok": True}
