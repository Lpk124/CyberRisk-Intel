"""add incident end date

Revision ID: b31e6f24a908
Revises: 8d2a6b7c41f0
Create Date: 2026-09-01 18:05:00
"""

import sqlalchemy as sa
from alembic import op

revision = "b31e6f24a908"
down_revision = "8d2a6b7c41f0"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("security_event", sa.Column("incident_end_date", sa.Date(), nullable=True))


def downgrade() -> None:
    op.drop_column("security_event", "incident_end_date")
