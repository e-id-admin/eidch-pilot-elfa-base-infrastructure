# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid 

from sqlalchemy import Column
from sqlalchemy.dialects.postgresql import UUID, JSON

import common.db.postgres as db


class TrustedIssuer(db.Base):
    __tablename__ = "issuer"
    id: UUID = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    public_key_set: dict = Column(JSON, nullable=False)
    nonce: UUID = Column(UUID(as_uuid=True), nullable=False)
