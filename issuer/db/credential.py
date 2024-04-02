# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Storage for issued credential-offers
"""

import uuid
import time
import logging
from enum import Enum
import sqlalchemy.orm as sa_orm
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import ForeignKey
from sqlalchemy import Integer, select, and_, or_
from sqlalchemy.dialects.postgresql import UUID, JSON, TEXT, BOOLEAN


import common.db.postgres as db
from issuer.db.status_list import StatusList, get_status_list_orm

from issuer.logging import IssuerOperationsLogEntry

_logger = logging.getLogger(__name__)


class CredentialManagement(db.Base):
    """
    Management Entry for Credentials
    """

    __tablename__ = "credential_management"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    credential_status: Mapped[str] = mapped_column(TEXT, nullable=True)
    credential_offer: Mapped["CredentialOffer"] = sa_orm.relationship(back_populates="management")
    status_list_associations: Mapped[list["StatusListCredentialManagementAssociation"]] = sa_orm.relationship(back_populates="management")


class StatusListCredentialManagementAssociation(db.Base):
    """
    Association Table to enale n:m realtionship between CredentialManagement and StatusList
    """

    __tablename__ = "status_list_credential_management_association"
    status_list_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(StatusList.id), primary_key=True)
    status_list: Mapped[StatusList] = sa_orm.relationship()

    management_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(CredentialManagement.id), primary_key=True)
    management: Mapped[CredentialManagement] = sa_orm.relationship(back_populates="status_list_associations")

    status_list_index: Mapped[str] = mapped_column(Integer, nullable=True)
    """
    Index used on the status list. This will only be set once the credential is issued.
    """


class CredentialOffer(db.Base):
    """
    Pending Credential Offers
    """

    __tablename__ = "credential_offer"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    """ID for the Offer, doubles as pre-auth-code"""
    metadata_credential_supported_id: Mapped[str] = mapped_column(TEXT, nullable=False)
    pin: Mapped[str] = mapped_column(TEXT, nullable=True)
    """Optional Pin for credential redemption"""
    management_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey(CredentialManagement.id), nullable=False)
    management: Mapped[CredentialManagement] = sa_orm.relationship(back_populates="credential_offer")
    is_selective_disclosure: Mapped[bool] = mapped_column(BOOLEAN, nullable=False)
    access_token: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4, index=True)
    offer_expiration_timestamp: Mapped[int] = mapped_column(Integer)
    """
    Expiration time in seconds since 1.1.1970
    Offer is not anymore valid if the curren time > expiration_time
    """
    nonce: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), default=uuid.uuid4)
    """Nonce to be used for renewal"""
    offer_data: Mapped[dict] = mapped_column(JSON, nullable=False)
    """Data issued in the credential """
    credential_valid_from: Mapped[str] = mapped_column(TEXT, nullable=True)
    """ISO8601 Format Datetime from when the credential should be valid"""
    credential_valid_until: Mapped[str] = mapped_column(TEXT, nullable=True)
    """ISO8601 Format Datetime until when the credential will be valid"""

    def validity_check(self) -> bool:
        """
        Checks if the expiration_time for the offer has been reached.
        If the Offer is expired, logs expiration, updates management state & deletes subject data.
        Only checks offers which are in offered state.
        returns true if the offer is still valid
        """
        if self.management.credential_status != CredentialStatus.OFFERED.value:
            # Offer has been used; not valid any more
            return False
        if self.offer_expiration_timestamp > time.time():
            # Offer not yet expired
            return True
        # Offer expired & cleanup not yet done

        _logger.info(
            IssuerOperationsLogEntry(
                message="Offer expired.",
                status=IssuerOperationsLogEntry.Status.error,
                operation=IssuerOperationsLogEntry.Operation.issuance,
                step=IssuerOperationsLogEntry.Step.issuance_expiry,
                management_id=self.management_id,
            ),
        )

        self.remove_offer_data()
        self.management.credential_status = CredentialStatus.EXPIRED.value

    def remove_offer_data(self) -> None:
        """Replaces the offer data with an empty dictionary"""
        self.offer_data = {}


class CredentialStatus(Enum):
    OFFERED = "Offered"
    CANCELLED = "Cancelled"
    IN_PROGRESS = "Claiming in Progress"
    ISSUED = "Issued"
    SUSPENDED = "Suspended"
    REVOKED = "Revoked"
    EXPIRED = "Expired"

    @classmethod
    def is_post_holder_interaction(cls: "CredentialStatus", to_compare: str) -> bool:
        """Checks if the status indicates that a holder interaction did already take place.

        Args:
            cls (CredentialStatus): Reference to own class.
            to_compare (str): string which contains the actual status value.

        Returns:
            bool: true if the holder already interacted with this VC.
        """
        return to_compare not in [cls.OFFERED.value, cls.IN_PROGRESS.value, cls.CANCELLED.value]

    @classmethod
    def is_during_holder_interaction(cls: "CredentialStatus", to_compare: str) -> bool:
        return to_compare in [cls.IN_PROGRESS.value]

    @classmethod
    def purpose_to_status(cls: "CredentialStatus", purpose: str) -> "CredentialStatus":
        match purpose.lower():
            case "suspension":
                return CredentialStatus.SUSPENDED
            case "revocation":
                return CredentialStatus.REVOKED
            case _:
                return None


# TODO -> EID-1248: Do not use conf in this file


def register_offer(
    session: sa_orm.Session,
    metadata_credential_supported_id: str,
    status_list_ids: list[uuid.UUID],
    offer_id: uuid.UUID,  # This is the pre-auth code
    offer_data: dict,
    offer_expiration_timestamp: int,
    pin: str = None,
    valid_from: str = None,
    valid_until: str = None,
    is_selective_disclosure=True,
):
    """
    Registers an offer to be consumed using openid4vc
    """
    # TODO -> EID-1248: Create CredentialManagement Entry
    management_id = uuid.uuid4()
    status_lists = [get_status_list_orm(status_list_id, session) for status_list_id in status_list_ids]
    management_obj = CredentialManagement(id=management_id, credential_status=CredentialStatus.OFFERED.value)
    session.add(management_obj)
    for status_list in status_lists:
        association = StatusListCredentialManagementAssociation(status_list=status_list, management=management_obj)
        session.add(association)
    session.add(
        CredentialOffer(
            id=offer_id,
            metadata_credential_supported_id=metadata_credential_supported_id,
            offer_data=offer_data,
            pin=pin,
            management=management_obj,
            is_selective_disclosure=is_selective_disclosure,
            offer_expiration_timestamp=offer_expiration_timestamp,
            credential_valid_from=valid_from,
            credential_valid_until=valid_until,
        )
    )
    return management_id


def get_offer(session: sa_orm.Session, offer_id: uuid.UUID) -> CredentialOffer | None:
    """
    Gets the offer (if any) by parameters as received in the /token step
    """
    return session.scalars(select(CredentialOffer).where(and_(CredentialOffer.id == offer_id))).one_or_none()


def get_offer_by_access_token_nonce(session: sa_orm.Session, access_token: str | uuid.UUID, nonce: str | uuid.UUID) -> CredentialOffer | None:
    """
    Gets the offer (if any) by parameters as received in the /credentials step
    """
    return session.scalars(select(CredentialOffer).where(and_(CredentialOffer.access_token == access_token, CredentialOffer.nonce == nonce))).one_or_none()


def get_management_object(session: sa_orm.Session, management_id: uuid.UUID) -> CredentialManagement | None:
    return session.scalars(select(CredentialManagement).where(CredentialManagement.id == management_id)).one_or_none()


def get_new_expired_offers(session: sa_orm.Session, limit_seconds: int = 86400) -> list[CredentialOffer]:
    """Returns all offers which are time expired, but do not have expired status yet"""
    return session.scalars(
        select(CredentialOffer)
        .join(CredentialOffer.management)
        .where(
            and_(
                and_(CredentialOffer.offer_expiration_timestamp <= round(time.time()), CredentialOffer.offer_expiration_timestamp > round(time.time()) - limit_seconds),
                or_(
                    # Offer has never been consumed...
                    CredentialManagement.credential_status == CredentialStatus.OFFERED.value,
                    # The wallet did crash during remeeing and never took it up again...
                    CredentialManagement.credential_status == CredentialStatus.IN_PROGRESS.value,
                ),
            )
        )
    ).all()
