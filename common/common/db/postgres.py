# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
from typing import Annotated
from collections.abc import Generator

from functools import cache
import logging
from common.config import inject_db_config

from sqlalchemy import create_engine, inspect, event
from sqlalchemy.orm import declarative_base, sessionmaker, DeclarativeBase, Session
from sqlalchemy.schema import CreateSchema
import sqlalchemy.exc

from alembic import command as alembic_command
from alembic.config import Config as AlembicConfig

from fastapi import Depends, status, HTTPException

#################
# DB Definition #
#################

_logger = logging.getLogger(__name__)


Base: DeclarativeBase = declarative_base()


def alembic_upgrade(alembic_config_file: str):
    if not os.path.exists(alembic_config_file):
        _logger.error(f"{alembic_config_file=} does not exist!")
    alembic_config = AlembicConfig(alembic_config_file)
    alembic_config.set_main_option(
        'script_location',
        os.path.join(os.path.dirname(alembic_config_file), "alembic"),
    )
    alembic_command.upgrade(alembic_config, 'head')
    logging.info("Alembic Upgrade Done")


@cache
def _setup_db(db_connection_string: str, db_schema: str):
    """Sets up a DB connection with the schema"""
    engine = create_engine(db_connection_string)

    @event.listens_for(engine, "connect", insert=True)
    def set_search_path(dbapi_connection, connection_record):
        """
        Setting Session search path every time a new connection is made
        https://docs.sqlalchemy.org/en/20/dialects/postgresql.html#setting-alternate-search-paths-on-connect
        """
        existing_autocommit = dbapi_connection.autocommit
        dbapi_connection.autocommit = True
        cursor = dbapi_connection.cursor()
        cursor.execute("SET SESSION search_path TO '%s'" % db_schema)
        cursor.close()
        dbapi_connection.autocommit = existing_autocommit

    inspector = inspect(engine)
    if db_schema not in inspector.get_schema_names():
        # Read only Registries do not have right to write, so just trying to create with if not exists will create an error
        with engine.connect() as conn:
            conn.execute(CreateSchema(db_schema, if_not_exists=True))
            conn.commit()

    _session_local = sessionmaker(bind=engine)
    return engine, _session_local


def session(db_connection_string: str, db_schema: str) -> Session:
    try:
        engine, _session_local = _setup_db(db_connection_string, db_schema)
        db_session = _session_local()
        return db_session
    except sqlalchemy.exc.OperationalError:
        # TODO -> EID-1238: Log in a smart way
        _logger.exception("Could not establish connection to database.")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Could not establish connection to database",
        )


def env_session(db_config: inject_db_config) -> Generator[Session, None, None]:
    db_session = session(
        db_connection_string=db_config.SQLALCHEMY_DATABASE_URL,
        db_schema=db_config.SQLALCHEMY_DATABASE_SCHEMA,
    )
    try:
        yield db_session
    finally:
        db_session.close()


inject = Annotated[Session, Depends(env_session)]
