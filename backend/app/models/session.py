from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TimestampMixin, UUIDMixin

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability


class ResearchSession(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "research_sessions"

    target_ip: Mapped[str] = mapped_column(String(255), nullable=False)
    target_hostname: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="pending",
        server_default="pending",
    )
    phase: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        default="reconnaissance",
        server_default="reconnaissance",
    )
    iteration: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vulnerability_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    critical_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    high_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0, server_default="0")
    config: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")
    scan_profile: Mapped[str] = mapped_column(String(50), nullable=False, default="deep", server_default="deep")
    agent_mode: Mapped[str] = mapped_column(String(50), nullable=False, default="multi_agent", server_default="multi_agent")
    network_topology: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")

    vulnerabilities: Mapped[List["Vulnerability"]] = relationship(
        "Vulnerability",
        back_populates="session",
        cascade="all, delete-orphan",
    )


class AppSettings(Base):
    __tablename__ = "app_settings"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")
    value_type: Mapped[str] = mapped_column(
        String(50),
        nullable=False,
        default="string",
        server_default="string",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )


# Import the dependent model after ResearchSession is declared so SQLAlchemy's
# string relationship target is registered even when callers import only
# AppSettings from this module before querying settings.
from app.models.vulnerability import Vulnerability as Vulnerability  # noqa: E402,F401
