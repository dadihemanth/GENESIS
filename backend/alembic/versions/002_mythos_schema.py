"""GENESIS schema: attack chains, patches, MITRE, scan profiles, network topology

Revision ID: 002
Revises: 001
Create Date: 2026-04-23 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ---- vulnerabilities ----
    op.add_column("vulnerabilities", sa.Column("patch_code", sa.Text(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("verification_status", sa.String(50), server_default="unverified", nullable=False))
    op.add_column("vulnerabilities", sa.Column("attack_chain_id", sa.String(100), nullable=True))
    op.add_column("vulnerabilities", sa.Column("chain_position", sa.Integer(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("mitre_techniques", sa.JSON(), server_default="[]", nullable=False))
    op.add_column("vulnerabilities", sa.Column("is_zero_day", sa.Boolean(), server_default="false", nullable=False))
    op.create_index("ix_vulnerabilities_attack_chain_id", "vulnerabilities", ["attack_chain_id"])

    # ---- research_sessions ----
    op.add_column("research_sessions", sa.Column("scan_profile", sa.String(50), server_default="deep", nullable=False))
    op.add_column("research_sessions", sa.Column("agent_mode", sa.String(50), server_default="solo", nullable=False))
    op.add_column("research_sessions", sa.Column("network_topology", sa.JSON(), server_default="{}", nullable=False))


def downgrade() -> None:
    op.drop_index("ix_vulnerabilities_attack_chain_id", table_name="vulnerabilities")
    op.drop_column("vulnerabilities", "is_zero_day")
    op.drop_column("vulnerabilities", "mitre_techniques")
    op.drop_column("vulnerabilities", "chain_position")
    op.drop_column("vulnerabilities", "attack_chain_id")
    op.drop_column("vulnerabilities", "verification_status")
    op.drop_column("vulnerabilities", "patch_code")
    op.drop_column("research_sessions", "network_topology")
    op.drop_column("research_sessions", "agent_mode")
    op.drop_column("research_sessions", "scan_profile")
