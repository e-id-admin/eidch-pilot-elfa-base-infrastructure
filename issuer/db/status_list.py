# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import common.db.postgres as db
from sqlalchemy.dialects.postgresql import TEXT, UUID
from sqlalchemy.orm import Mapped, mapped_column

import sqlalchemy.orm as sa_orm
from sqlalchemy import Integer, select

import common.status_list as sl

import uuid


class StatusList(db.Base):
    """
    StatusList Data for creating the VC
    """

    __tablename__ = "status_list"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    purpose: Mapped[str] = mapped_column(TEXT, nullable=False)
    current_index: Mapped[int] = mapped_column(Integer, nullable=False)
    data_zip: Mapped[str] = mapped_column(TEXT, nullable=False)
    issuer_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False)


def create_status_list(session: sa_orm.Session, issuer_id: uuid.UUID, status_list_id: uuid.UUID, purpose: str, initial_size: int = 100000) -> sl.StatusList2021:
    """
    Creates a new empty status list
    """
    list_obj = sl.create_empty(initial_size)
    instance = StatusList(id=status_list_id, purpose=purpose, current_index=0, data_zip=list_obj.pack(), issuer_id=issuer_id)
    session.add(instance)
    session.commit()
    return list_obj


def get_status_list(status_list_id: uuid.UUID, session: sa_orm.Session) -> sl.StatusList2021:
    orm_list = get_status_list_orm(status_list_id, session)
    return sl.from_string(orm_list.data_zip)


def get_status_list_orm(status_list_id: uuid.UUID, session: sa_orm.Session) -> StatusList:
    status_list = session.scalars(select(StatusList).where(StatusList.id == status_list_id)).one()
    return status_list


def use_statuslist_index(status_list_id: uuid.UUID, session: sa_orm.Session) -> str:
    # TODO -> EID-1254: consider thread safty here... possibly lock the table?
    status_list = get_status_list_orm(status_list_id, session)
    # Luckily for us, python handles very large number
    status_list.current_index = str(int(status_list.current_index) + 1)
    session.add(status_list)
    return status_list.current_index
