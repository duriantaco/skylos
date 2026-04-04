from pydantic import BaseModel


class User(BaseModel):
    name: str

    def model_post_init(self, __context):
        return None
