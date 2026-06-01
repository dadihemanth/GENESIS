from __future__ import annotations

from typing import Optional

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
    # T21 — Neo4j attack knowledge graph
    neo4j_uri: str = Field(default="bolt://localhost:7687", alias="NEO4J_URI")
    neo4j_user: str = Field(default="neo4j", alias="NEO4J_USER")
    neo4j_password: str = Field(default="", alias="NEO4J_PASSWORD")
    # T23 — MinIO shared artifact store (optional). When endpoint is empty
    # the ArtifactResolver falls back to local filesystem paths only — that
    # keeps single-host deployments working unchanged.
    minio_endpoint: str = Field(default="", alias="MINIO_ENDPOINT")
    minio_access_key: str = Field(default="", alias="MINIO_ACCESS_KEY")
    minio_secret_key: str = Field(default="", alias="MINIO_SECRET_KEY")
    minio_bucket: str = Field(default="genesis-artifacts", alias="MINIO_BUCKET")
    minio_secure: bool = Field(default=False, alias="MINIO_SECURE")
    # Celery worker self-reported capability tags — comma-separated, e.g.
    # "ghidra,fuzzer,instrumentation". Workers with no tags serve every
    # queue as today.
    worker_capabilities: str = Field(default="", alias="WORKER_CAPABILITIES")

    # Anthropic / LLM
    anthropic_api_key: str = Field(default="", alias="ANTHROPIC_API_KEY")
    llm_model: str = Field(default="claude-opus-4-7", alias="LLM_MODEL")
    llm_max_tokens: int = Field(default=8096, alias="LLM_MAX_TOKENS")
    llm_temperature: float = Field(default=0.7, alias="LLM_TEMPERATURE")

    # Azure AI Foundry (optional) — set in UI settings, not env
    azure_endpoint: str = Field(default="", alias="AZURE_ENDPOINT")

    # validation milestone 1 — cross-model adversarial debate.
    # When set, the Blue (debater) agent in RedBlueDialectic uses a different
    # model/provider than the Red (auditor) agent. Hypotheses that survive a
    # cross-model challenge are tagged `cross_model_confirmed` (+0.2 stake).
    # Leave empty to use the same model for both Red and Blue (legacy behaviour).
    # Typically: if LLM_MODEL is a Claude model, set these to a GPT deployment.
    debate_model: str = Field(default="", alias="DEBATE_MODEL")
    debate_provider: str = Field(default="", alias="DEBATE_PROVIDER")

    # MCP Server
    mcp_host: str = Field(default="localhost", alias="MCP_HOST")
    mcp_port: int = Field(default=3001, alias="MCP_PORT")
    mcp_api_key: str = Field(default="", alias="MCP_API_KEY")

    # Research limits
    max_iterations: Optional[int] = Field(default=None, alias="MAX_ITERATIONS")
    # Minimum iteration floor — no termination signal (FINAL_REPORT,
    # SESSION_COMPLETE, idle-stop) is honoured before the orchestrator
    # has run at least this many iterations. If max_iterations < this,
    # max_iterations is silently clamped upward to the floor.
    min_iterations: int = Field(default=50, alias="MIN_ITERATIONS")
    # Session-scoped (tool, params_hash, target) dedup. The 3rd time a
    # triple is invoked the orchestrator returns ALREADY_EXECUTED instead
    # of running the probe. 2-strike rule protects legitimate retries.
    dedup_threshold: int = Field(default=2, alias="DEDUP_THRESHOLD")
    # Iteration at which the orchestrator dispatches a `deliberate`
    # reasoning loop on behalf of the agent if the agent has not done
    # so itself — backstop that guarantees one loop_state document per
    # session even with a non-compliant agent.
    loop_backstop_iter: int = Field(default=8, alias="LOOP_BACKSTOP_ITER")
    scan_timeout: int = Field(default=3600, alias="SCAN_TIMEOUT")
    storage_path: str = Field(default="/data/security", alias="STORAGE_PATH")

    # App security
    secret_key: str = Field(default="change-me-in-production-supersecret", alias="SECRET_KEY")
    api_key: str = Field(default="", alias="API_KEY")

    # v5 settings
    max_reasoning_depth: int = Field(default=5, alias="MAX_REASONING_DEPTH")
    hypothesis_market_threshold: float = Field(default=0.3, alias="HYPOTHESIS_MARKET_THRESHOLD")
    surface_watch_interval: int = Field(default=3600, alias="SURFACE_WATCH_INTERVAL")
    cve_extrapolator_enabled: bool = Field(default=True, alias="CVE_EXTRAPOLATOR_ENABLED")
    github_token: str = Field(default="", alias="GITHUB_TOKEN")

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
