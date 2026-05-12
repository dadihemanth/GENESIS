"""v5 schema: tool_registry table for T97 synthesized tools

Revision ID: 003
Revises: 002
Create Date: 2026-05-04 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "003"
down_revision: Union[str, None] = "002"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "tool_registry",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("name", sa.String(200), nullable=False, unique=True),
        sa.Column("capability_tag", sa.String(100), nullable=False, server_default="custom"),
        sa.Column("language", sa.String(50), nullable=False, server_default="python"),
        sa.Column("minio_path", sa.Text(), nullable=True),
        sa.Column("script_hash", sa.String(64), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("session_created", sa.String(100), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
    )
    op.create_index("ix_tool_registry_capability_tag", "tool_registry", ["capability_tag"])
    op.create_index("ix_tool_registry_script_hash", "tool_registry", ["script_hash"])


def downgrade() -> None:
    op.drop_index("ix_tool_registry_capability_tag", table_name="tool_registry")
    op.drop_index("ix_tool_registry_script_hash", table_name="tool_registry")
    op.drop_table("tool_registry")
