from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_env: str = "development"
    app_secret_key: str = "change-me"
    cors_origins: str = "http://localhost:5173,http://localhost:8080"

    alerts_db_path: str = "/app/data/alerts.db"
    mitigations_db_path: str = "/app/data/mitigations.db"
    kuma_status_db_path: str = "/app/data/kuma_status.db"

    clickhouse_host: str = "clickhouse"
    clickhouse_port: int = 8123
    clickhouse_user: str = "alert_center"
    clickhouse_password: str = "change-me"
    clickhouse_database: str = "alert_center"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    @property
    def allowed_origins(self) -> list[str]:
        return [item.strip() for item in self.cors_origins.split(",") if item.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
