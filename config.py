from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    APP_NAME: str = "GreenRoots"
    APP_ENV: str = "development"

    SECRET_KEY: str
    DATABASE_URL: str

    SESSION_HTTPS_ONLY: bool | None = None

    model_config = SettingsConfigDict(
        env_file=".env",
        extra="ignore"
    )

    def model_post_init(self, __context):
        if self.SESSION_HTTPS_ONLY is None:
            self.SESSION_HTTPS_ONLY = (
                self.APP_ENV.lower() == "production"
            )


settings = Settings()