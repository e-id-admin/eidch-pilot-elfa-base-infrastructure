# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Models for the controller of the issuer.
These models are not based on any international standard
"""

import datetime
from uuid import UUID
from typing import Optional
from pydantic import BaseModel, field_serializer


class CredentialOfferData(BaseModel):
    """
    Data for creating a credential offer
    """

    metadata_credential_supported_id: str
    """
    ID as in credential metadata
    """
    credential_subject_data: dict
    """
    Data to be used in VC
    """
    pin: str | None = None
    """
    Pin-code required together with pre-auth code.
    Dont set it to require no pin
    """
    offer_validity_seconds: int = 60 * 60 * 24 * 30  # 30 Days
    """
    Validitiy how long the offer should be usable.
    """
    credential_valid_until: Optional[datetime.datetime] = None
    """
    XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
    eg. 2010-01-01T19:23:24Z
    """
    credential_valid_from: Optional[datetime.datetime] = None
    """
    XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
    eg. 2010-01-01T19:23:24Z
    """

    @field_serializer('credential_valid_until', 'credential_valid_from')
    def serialize_xml_date_time_stamp(self, value: datetime.datetime):
        return value.isoformat(timespec='seconds')


class CredentialOfferResponse(BaseModel):
    management_id: UUID
    """
    ID for the conntroller to revoke, poll status, etc of the offer / credential
    """
    offer_deeplink: str
    """
    Deep link to be provided (maybe as QR-Code) to the Holder
    """
