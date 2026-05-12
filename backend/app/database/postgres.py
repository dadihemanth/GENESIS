from __future__ import annotations

from typing import AsyncGenerator

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.config import settings

# NullPool (no pooling): every session opens a fresh asyncpg connection and
# closes it immediately. We use this because the backend is a Celery worker
# that spins a new asyncio event loop per task (`asyncio.run(...)`), and
# pooled asyncpg connections carry a bound reference to the loop they were
# created on. When a later task tries to reuse one of those connections the
# cleanup path calls `self._loop.create_task(...)` on the dead loop and
# raises `RuntimeError: Event loop is closed`. NullPool eliminates that
# class of bug at the cost of a few ms of connection-open overhead per
# request — totally fine for an operator-facing UI.
engine = create_async_engine(
    settings.database_url,
    echo=False,
    poolclass=NullPool,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    from app.models.base import Base
    # Import all models so they register with Base.metadata
    import app.models.session  # noqa: F401
    import app.models.vulnerability  # noqa: F401
    import app.models.user  # noqa: F401  — v6: tenants, users, audit_log, goals, event_log, budget_controls

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


DEFAULT_SETTINGS = [
    ("llm_provider", "anthropic", "string"),  # anthropic | azure | bedrock | custom
    ("llm_api_key", "", "string"),
    ("llm_model", "claude-sonnet-4-6", "string"),
    ("llm_max_tokens", "8096", "int"),
    ("llm_temperature", "0.7", "float"),
    ("azure_endpoint", "", "string"),
    # T13 · Bedrock provider (AWS-signed Anthropic on Amazon Bedrock)
    ("aws_region", "us-east-1", "string"),
    ("aws_access_key", "", "string"),
    ("aws_secret_key", "", "string"),
    ("aws_session_token", "", "string"),
    # T13 · Custom / research endpoint (Glasswing-style preview)
    ("custom_endpoint", "", "string"),
    ("custom_headers", "", "string"),  # "Header: value, Header2: value2"
    ("mcp_host", "mcp_server", "string"),
    ("mcp_port", "3001", "int"),
    ("max_iterations", "20", "int"),
    ("scan_timeout", "3600", "int"),
    ("storage_path", "/data/security", "string"),
    ("setup_complete", "false", "bool"),
]


async def init_default_settings() -> None:
    from app.models.session import AppSettings

    async with AsyncSessionLocal() as session:
        for key, value, value_type in DEFAULT_SETTINGS:
            result = await session.execute(
                select(AppSettings).where(AppSettings.key == key)
            )
            existing = result.scalar_one_or_none()
            if existing is None:
                session.add(AppSettings(key=key, value=value, value_type=value_type))
        await session.commit()
