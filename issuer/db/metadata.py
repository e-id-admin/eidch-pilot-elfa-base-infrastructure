# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Storage for metadata for openid-credential-issuer endpoint
"""
import json
import uuid
import sqlalchemy.orm as sa_orm
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import select
from sqlalchemy.dialects.postgresql import UUID, JSON
import common.db.postgres as db

##########
# Tables #
##########


class CredentialMetadata(db.Base):
    """
    For now a metadata buffer
    """

    __tablename__ = "credential_metadata"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    credential_metadata: Mapped[dict] = mapped_column(JSON, nullable=False)


#############
# Functions #
#############


def set_metadata(session: sa_orm.Session, metadata: dict) -> None:
    """
    Removes any existing metadata entries and writes the given json
    """
    old_metadata = session.scalars(select(CredentialMetadata)).all()
    for old in old_metadata:
        session.delete(old)
    new_metadata = CredentialMetadata(credential_metadata=metadata)
    session.add(new_metadata)
    session.commit()


def get_metadata(session: sa_orm.Session) -> dict | None:
    data = session.scalars(select(CredentialMetadata.credential_metadata)).one_or_none()
    # TODO -> EID-1240: Find out why sqlalchemy is returning a string instead of correctly mapped json here
    if data:
        data = json.loads(data)
    return data
