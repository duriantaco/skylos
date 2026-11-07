from pydantic import BaseModel
from pydantic_settings import BaseSettings


class ProfileModel(BaseModel):
    name: str


class RuntimeSettings(BaseSettings):
    api_url: str = "https://example.com"


class DraftModel(BaseModel):
    name: str


class DraftSettings(BaseSettings):
    api_url: str = "https://example.com"


profile = ProfileModel(name="Ada")
settings = RuntimeSettings()
print(profile.name, settings.api_url)
