# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Add validity period to offers

Alters Table credential_offer 
* rename expiration_time to a clearer offer_expiration_timestamp
* add credential_valid_from & credential_valid_until

Revision ID: 1.1
Revises: 1.0
Create Date: 2024-02-12 09:46:17.971636

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '1.1'
down_revision: Union[str, None] = '1.0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table(table_name="credential_offer") as credential_offer_upgrade:
        credential_offer_upgrade.alter_column(
            column_name="expiration_time",
            new_column_name="offer_expiration_timestamp",
        )
        credential_offer_upgrade.add_column(
            sa.Column(
                "credential_valid_from",
                sa.TEXT,
                nullable=True,
            ),
        )
        credential_offer_upgrade.add_column(
            sa.Column(
                "credential_valid_until",
                sa.TEXT,
                nullable=True,
            ),
        )


def downgrade() -> None:
    pass
