# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""init

Revision ID: 1.0
Revises: 
Create Date: 2024-02-09 11:12:59.698460

First Addition of Alembic.
Will check if tables already exist before attempting to forcefully create them.

"""

import uuid
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1.0'
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Check DB if things already exist.
    # There are systems already in place which
    # may not need their tabels to be brought to V1
    inspector = sa.Inspector.from_engine(op.get_bind())
    existing_tables = inspector.get_table_names()
    if "credential_metadata" not in existing_tables:
        op.create_table(
            "credential_metadata",
            sa.Column("id", sa.UUID, primary_key=True),
            sa.Column("credential_metadata", sa.JSON),
        )
    if "status_list" not in existing_tables:
        op.create_table(
            "status_list",
            sa.Column("id", sa.UUID, primary_key=True),
            sa.Column("issuer_id", sa.UUID, nullable=False),
            sa.Column("purpose", sa.TEXT, nullable=False),
            sa.Column("current_index", sa.INTEGER, nullable=False),
            sa.Column("data_zip", sa.TEXT, nullable=False),
        )
    if "credential_management" not in existing_tables:
        op.create_table(
            "credential_management",
            sa.Column("id", sa.UUID, primary_key=True),
            sa.Column("credential_status", sa.TEXT, nullable=False),
        )
    if "status_list_credential_management_association" not in existing_tables:
        op.create_table(
            "status_list_credential_management_association",
            sa.Column("status_list_id", sa.UUID, nullable=False, primary_key=True),
            sa.Column("management_id", sa.UUID, nullable=False, primary_key=True),
            sa.Column("status_list_index", sa.INTEGER, nullable=True),
            sa.ForeignKeyConstraint(
                columns=["status_list_id"],
                refcolumns=["status_list.id"],
            ),
            sa.ForeignKeyConstraint(
                columns=["management_id"],
                refcolumns=["credential_management.id"],
            ),
        )
    if "credential_offer" not in existing_tables:
        op.create_table(
            "credential_offer",
            sa.Column("id", sa.UUID, primary_key=True),
            sa.Column("metadata_credential_supported_id", sa.TEXT, nullable=False),
            sa.Column("offer_data", sa.JSON, nullable=False),
            sa.Column("pin", sa.TEXT, nullable=True),
            sa.Column("management_id", sa.UUID, nullable=False),
            sa.Column("is_selective_disclosure", sa.BOOLEAN, nullable=False),
            sa.Column("access_token", sa.UUID, nullable=True, default=uuid.uuid4),
            sa.Column("expiration_time", sa.INTEGER, nullable=True),
            sa.Column("nonce", sa.UUID, nullable=False, default=uuid.uuid4),
            sa.ForeignKeyConstraint(
                columns=["management_id"],
                refcolumns=["credential_management.id"],
            ),
        )


def downgrade() -> None:
    pass
