from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    debug: bool = False

    class Config:
        env_file = ".env"
        extra = "ignore"

    class Options:
        verbose = True


settings = Settings()
print(settings.debug)
