"""allow unknown incident date

Revision ID: 8d2a6b7c41f0
Revises: 4c7f8e3a91d2
Create Date: 2026-09-01 17:45:00
"""

import sqlalchemy as sa
from alembic import op

revision = "8d2a6b7c41f0"
down_revision = "4c7f8e3a91d2"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("security_event") as batch_op:
        batch_op.alter_column("incident_date", existing_type=sa.Date(), nullable=True)


def downgrade() -> None:
    with op.batch_alter_table("security_event") as batch_op:
        batch_op.alter_column("incident_date", existing_type=sa.Date(), nullable=False)
