from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_url: str = "http://localhost"
