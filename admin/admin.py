# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import base64

from asgi_correlation_id import CorrelationIdMiddleware

from sqlalchemy.sql.expression import select

from pydantic import BaseModel

from jwcrypto import jwk


from common.db.model.public_key import TrustedIssuer
from common.db.model.status_list import CredentialStatusList
from common.model.ietf import JSONWebKeySet
from common.status_list import StatusListRegistryData
from common.fastapi_extensions import ExtendedFastAPI

from admin.route.health import AdminHealthAPIRouter
from admin import config as conf
import admin.db as db

app = ExtendedFastAPI(conf.inject)

app.add_middleware(CorrelationIdMiddleware)


#################
# Base Registry #
#################


class PublicPEMKey(BaseModel):
    key_type: str
    """
    What would be in a JSON Web Key the kty
    eg. EC for elliptic curve
    """
    base64_encoded_key: str
    """
    The key as regular base64 encoded string.
    Note: Not URL-Encoded. Including trailing =
    """


# REST Endpoints #
# TODO ->  EID-1164: Consider removing get endpoints, as these are just duplicates from the public service.
@app.get("/issuers")
def get_issuers(session: db.base_db_inject) -> list[str]:
    issuers = session.execute(select(TrustedIssuer.id))
    return list(map(str, map(lambda i: i[0], issuers)))


@app.get("/issuer/{issuer_id}")
def get_issuer_by_id(issuer_id: uuid.UUID, session: db.base_db_inject):
    issuer = session.execute(select(TrustedIssuer).where(TrustedIssuer.id == issuer_id)).first()[0]
    return issuer


@app.get("/issuer/{issuer_id}/nonce")
def get_issuer_nonce(issuer_id: uuid.UUID, session: db.base_db_inject) -> uuid.UUID:
    issuer_nonce: uuid.UUID = session.execute(select(TrustedIssuer.nonce).where(TrustedIssuer.id == issuer_id)).first()[0]
    return issuer_nonce


@app.put("/issuer")
def allocate_new_issuer(issuer_public_keys: JSONWebKeySet | list[PublicPEMKey], session: db.base_db_inject):
    """
    issuer_public_keys as JSON Web Key Set or a list of base64 encoded .pem keys.
    """
    if isinstance(issuer_public_keys, list):
        keys = [jwk.JWK.from_pem(base64.b64decode(key.base64_encoded_key)) for key in issuer_public_keys]
        issuer_public_keys = JSONWebKeySet.model_validate({"keys": keys})

    issuer = TrustedIssuer(public_key_set=issuer_public_keys.model_dump(exclude_none=True), nonce=uuid.uuid4())
    session.add(issuer)
    session.commit()
    session.refresh(issuer)
    return issuer


#######################
# Revocation Registry #
#######################


# REST Endpoints #
@app.put("/issuer/{issuer_id}/status-list")
def create_new_status_list(issuer_id: uuid.UUID, session: db.revocation_db_inject) -> StatusListRegistryData:
    """
    This operation should only be done by the admin
    """
    status_list = CredentialStatusList(issuer_id=issuer_id, status_credential_jwt="Not Initialized by Issuer", nonce=uuid.uuid4())
    session.add(status_list)
    session.flush()
    session.commit()
    session.refresh(status_list)
    return status_list


@app.get("/issuer/{issuer_id}/status-list")
def list_issuer_status_lists(issuer_id: uuid.UUID, session: db.revocation_db_inject) -> list[StatusListRegistryData]:
    status_lists = session.execute(
        select(
            CredentialStatusList.id,
            CredentialStatusList.issuer_id,
            CredentialStatusList.status_credential_jwt,
            CredentialStatusList.nonce,
        ).where(CredentialStatusList.issuer_id == issuer_id)
    ).all()
    return list(map(lambda sl: sl[0], status_lists))


@app.get("/issuer/{issuer_id}/status-list/{status_list_id}", responses={200: {"description": "JWT of the VC of the status_list"}})
def get_status_list(issuer_id: uuid.UUID, status_list_id: uuid.UUID, session: db.revocation_db_inject) -> str:
    """
    Returns the status list VC as a JWT
    """
    return session.execute(
        select(CredentialStatusList.status_credential_jwt).where(CredentialStatusList.issuer_id == issuer_id, CredentialStatusList.id == status_list_id)
    ).first()[0]


@app.get("/issuer/{issuer_id}/status-list/{status_list_id}/nonce")
def get_status_list_nonce(issuer_id: uuid.UUID, status_list_id: uuid.UUID, session: db.revocation_db_inject) -> uuid.UUID:
    """
    Returns the nonce needed by the issuer to update the status list
    """
    return session.execute(select(CredentialStatusList.nonce).where(CredentialStatusList.issuer_id == issuer_id, CredentialStatusList.id == status_list_id)).first()[0]


#############
#  Health   #
#############

app.include_router(AdminHealthAPIRouter())
