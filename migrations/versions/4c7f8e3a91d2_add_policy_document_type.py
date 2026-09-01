"""add policy document type

Revision ID: 4c7f8e3a91d2
Revises: e67c4b25c7bc
Create Date: 2026-09-01 17:20:00
"""

import sqlalchemy as sa
from alembic import op

revision = "4c7f8e3a91d2"
down_revision = "e67c4b25c7bc"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "policy",
        sa.Column("document_type", sa.Text(), nullable=False, server_default="other"),
    )


def downgrade() -> None:
    op.drop_column("policy", "document_type")
