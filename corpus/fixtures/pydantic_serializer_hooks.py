from pydantic import BaseModel, field_serializer, model_serializer


class User(BaseModel):
    name: str

    @field_serializer("name")
    def serialize_name(self, value):
        return value

    @model_serializer
    def serialize_model(self):
        return {"name": self.name}
