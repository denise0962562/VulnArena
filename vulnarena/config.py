from pydantic import Field, SecretStr, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="VULNARENA_", env_file=".env", extra="ignore")

    database_url: SecretStr = SecretStr("postgresql+asyncpg://vulnarena@127.0.0.1:5432/vulnarena")
    database_schema: str | None = Field(default=None, pattern=r"^[a-z_][a-z0-9_]*$")
    redis_url: str = "redis://localhost:6379/0"
    nvd_api_key: SecretStr = SecretStr("")
    deepseek_api_key: SecretStr = SecretStr("")
    deepseek_base_url: str = "https://api.deepseek.com"
    deepseek_model: str = "deepseek-chat"
    arena_timeout: float = Field(default=180.0, gt=10.0, le=600.0)
    arena_max_llm_calls: int = Field(default=8, ge=0, le=50)
    nvd_timeout: float = Field(default=30, gt=0, le=120)
    nvd_max_retries: int = Field(default=3, ge=0, le=5)
    nvd_interval: float = Field(default=6.1, gt=0)
    task_timeout: float = Field(default=300, gt=0, le=3600)
    lease_seconds: int = Field(default=60, ge=6)
    task_ttl: int = Field(default=86400, ge=3600)
    cache_ttl: int = Field(default=60, ge=1, le=3600)
    translation_model: str = "data/models/translate-en_zh-1_9"
    online_translation: bool = False

    @model_validator(mode="after")
    def validate_limits(self) -> "Settings":
        minimum = 0.61 if self.nvd_api_key.get_secret_value() else 6.1
        if self.nvd_interval < minimum:
            raise ValueError(f"nvd_interval must be >= {minimum} seconds")
        if self.task_ttl <= self.task_timeout + self.lease_seconds:
            raise ValueError("task_ttl must exceed task_timeout + lease_seconds")
        try:
            url = make_url(self.database_url.get_secret_value())
        except ArgumentError:
            raise ValueError("database_url must be a valid PostgreSQL URL") from None
        if url.drivername != "postgresql+asyncpg" or not url.database:
            raise ValueError("database_url must use postgresql+asyncpg and name a database")
        return self
