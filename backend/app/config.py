from __future__ import annotations

from pydantic import Field, computed_field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Database
    database_url: str = Field(
        default="postgresql+asyncpg://admin:SecureP@ssw0rd@localhost:5432/security_research",
        alias="DATABASE_URL",
    )
    mongodb_url: str = Field(
        default="mongodb://admin:SecureP@ssw0rd@localhost:27017/security_research?authSource=admin",
        alias="MONGODB_URL",
    )
    redis_url: str = Field(
        default="redis://localhost:6379",
        alias="REDIS_URL",
    )
    chroma_host: str = Field(default="localhost", alias="CHROMA_HOST")
    chroma_port: int = Field(default=8000, alias="CHROMA_PORT")

    # Anthropic / LLM
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    llm_model: str = Field(default="claude-opus-4-7", alias="LLM_MODEL")
    llm_max_tokens: int = Field(default=8096, alias="LLM_MAX_TOKENS")
    llm_temperature: float = Field(default=0.7, alias="LLM_TEMPERATURE")

    # Azure AI Foundry (optional) — set in UI settings, not env
    azure_endpoint: str = Field(default="", alias="AZURE_ENDPOINT")

    # MCP Server
    mcp_host: str = Field(default="localhost", alias="MCP_HOST")
    mcp_port: int = Field(default=3001, alias="MCP_PORT")
    mcp_api_key: str = Field(default="", alias="MCP_API_KEY")

    # Research limits
    max_iterations: int = Field(default=20, alias="MAX_ITERATIONS")
    scan_timeout: int = Field(default=3600, alias="SCAN_TIMEOUT")
    storage_path: str = Field(default="/data/security", alias="STORAGE_PATH")

    # App security
    secret_key: str = Field(default="change-me-in-production-supersecret", alias="SECRET_KEY")
    api_key: str = Field(default="", alias="API_KEY")

    # Celery
    celery_broker_url: str = Field(
        default="redis://localhost:6379/0",
        alias="CELERY_BROKER_URL",
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/1",
        alias="CELERY_RESULT_BACKEND",
    )

    @computed_field  # type: ignore[misc]
    @property
    def mcp_base_url(self) -> str:
        return f"http://{self.mcp_host}:{self.mcp_port}"


settings = Settings()
