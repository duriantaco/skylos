from alembic import op
import sqlalchemy as sa


revision = "20260425_add_orders"
down_revision = "20260424_previous"


def upgrade():
    op.create_table(
        "orders",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("name", sa.String(length=200), nullable=False),
    )


def downgrade():
    op.drop_table("orders")


def unused_migration_helper():
    return "manual only"


class UnusedMigrationState:
    pass
