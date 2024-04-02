# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import UUID, TEXT

import common.db.postgres as db


class CredentialStatusList(db.Base):
    __tablename__ = "statuslist"
    id: UUID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    issuer_id: UUID = Column(UUID(as_uuid=True), nullable=False)
    """
    ID of the issuer used in the base registry
    """
    status_credential_jwt: str = Column(TEXT, nullable=False)
    nonce: UUID = Column(UUID(as_uuid=True), nullable=False)
    """
    Nonce which the Issuer has to put into the VC, to prevent replay attacks
    """
