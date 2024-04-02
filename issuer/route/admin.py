# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Admin Functions to configure the issuer with metadata or perform a key rotation
"""
import fastapi
from fastapi import HTTPException, status

from common.apikey import require_api_key
import common.verifiable_credential as vc
import common.db.postgres as db
import common.model.ietf as ietf

from issuer import models
import issuer.db.metadata as db_metadata

TAG = "Admin"

router = fastapi.APIRouter(prefix="/oid4vc/admin", dependencies=[fastapi.Security(require_api_key)], tags=[TAG])


@router.post("/metadata")
def set_metadata(metadata: vc.OpenIDCredentialIssuerData, session: db.inject) -> None:
    """
    Defines the credential issuer metadata to be provded to calleers.
    Special Feature: If the MetadataCredentialSupported ID starts with "sd_" the credential will be
    issued as selective disclosure
    eg:
    * {"id": "my_credential"} will be issued as JWT
    * {"id": "sd_my_credential"} will be issued as SD-JWT
    """
    db_metadata.set_metadata(session, metadata.model_dump_json(exclude_none=True))


@router.patch("/jwks", description="Not yet implemented")
def update_json_web_key_set(jwks: ietf.JSONWebKeySet):
    # TODO -> EID-1428: Make key rotation work (& ensure we have one of the keys!)
    return HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED)


@router.patch("/status-lists")
def set_statuslist_configuration(new_config: list[models.StatusListConfiguration]):
    pass
