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
    if "issuer" not in existing_tables:
        op.create_table(
            "issuer",
            sa.Column("id", sa.UUID, primary_key=True, default=uuid.uuid4),
            sa.Column("public_key_set", sa.JSON, nullable=False),
            sa.Column("nonce", sa.UUID, nullable=False, default=uuid.uuid4),
        )


def downgrade() -> None:
    pass
