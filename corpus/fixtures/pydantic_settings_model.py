from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    api_url: str = "http://localhost"


class SettingsSnapshot:
    api_endpoint: str = "https://example.invalid"


print(Settings().api_url)
