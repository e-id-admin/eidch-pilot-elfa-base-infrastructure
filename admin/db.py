# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
from typing import Annotated

from sqlalchemy.orm import Session

from fastapi import Depends

import common.db.postgres as db


def get_session_base() -> Session:
    base_registry_session = db.session(
        os.getenv("DB_CONNECTION_BASE", "postgresql://postgres:mysecretpassword@db_base/registry"),
        db_schema=os.getenv("DB_SCHEMA_BASE", "openid4vc"),
    )
    try:
        yield base_registry_session
    finally:
        base_registry_session.close()


def get_session_revocation() -> Session:
    db.Base.metadata.schema = os.getenv("DB_SCHEMA_REVOCATION", "openid4vc")
    revocation_registry_session = db.session(
        os.getenv("DB_CONNECTION_REVOCATION", "postgresql://postgres:mysecretpassword@db_revocation/registry"),
        db_schema=os.getenv("DB_SCHEMA_REVOCATION", "openid4vc"),
    )
    try:
        yield revocation_registry_session
    finally:
        revocation_registry_session.close()


_base_db_depend = Depends(get_session_base)
base_db_inject = Annotated[Session, _base_db_depend]

_revocation_db_depend = Depends(get_session_revocation)
revocation_db_inject = Annotated[Session, _revocation_db_depend]
