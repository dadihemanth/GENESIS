from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import (
    BigInteger,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import Base, TimestampMixin, UUIDMixin


class UserRole(str, enum.Enum):
    admin = "admin"
    operator = "operator"
    reviewer = "reviewer"
    read_only = "read_only"


class Tenant(Base, UUIDMixin, TimestampMixin):
    """Org-level tenant for multi-tenant isolation (T141)."""
    __tablename__ = "tenants"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    neo4j_namespace: Mapped[str] = mapped_column(String(100), nullable=False, default="default")
    pg_schema_prefix: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    token_budget: Mapped[int] = mapped_column(Integer, nullable=False, default=1_000_000)


class User(Base, UUIDMixin, TimestampMixin):
    """Platform user with role-based access control (T142)."""
    __tablename__ = "users"

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True, index=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole, name="user_role"),
        nullable=False,
        default=UserRole.operator,
        server_default=UserRole.operator.value,
    )
    is_active: Mapped[bool] = mapped_column(nullable=False, default=True, server_default="true")
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)


class AuditLog(Base, UUIDMixin):
    """Immutable append-only audit trail (T142)."""
    __tablename__ = "audit_log"

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    extra: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class Goal(Base, UUIDMixin, TimestampMixin):
    """Operator-supplied natural-language goal compiled into an attack tree (T132)."""
    __tablename__ = "goals"

    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="SET NULL"), nullable=True
    )
    goal_text: Mapped[str] = mapped_column(Text, nullable=False)
    compiled_tree: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")
    status: Mapped[str] = mapped_column(
        String(50), nullable=False, default="active", server_default="active"
    )


class EventLog(Base):
    """Append-only event sourcing log per session (T146)."""
    __tablename__ = "event_log"

    seq: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    session_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("research_sessions.id", ondelete="CASCADE"), nullable=False, index=True
    )
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False, default=dict, server_default="{}")
    ts: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class BudgetControl(Base, UUIDMixin, TimestampMixin):
    """Per-target cost and resource budget controls (T145)."""
    __tablename__ = "budget_controls"

    tenant_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"), nullable=True
    )
    target_ip: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    monthly_usd_cap: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    token_budget: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    sandbox_cpu_cap: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    tool_call_cap: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
