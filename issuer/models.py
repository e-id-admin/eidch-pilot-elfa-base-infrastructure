# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
from pydantic import BaseModel, Field
from issuer.db.credential import CredentialStatus


class VcManagementInfo(BaseModel):
    """Summary of Credential Management ID & Status"""

    management_id: uuid.UUID = Field(alias="id")
    credential_status: CredentialStatus


class StatusListConfiguration(BaseModel):
    """
    Confiugration for a statuslist and what it is used for. Statuslist must exist in the statuslist registry.

    standardized purpose are: "revocation" and "suspension". Other string can be used, but may not be understood by verifiers
    """

    status_list_id: uuid.UUID
    purpose: str
