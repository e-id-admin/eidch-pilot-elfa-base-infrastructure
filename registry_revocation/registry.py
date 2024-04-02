# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import logging

from fastapi import APIRouter, HTTPException, status, Security
from asgi_correlation_id import CorrelationIdMiddleware
import httpx

from sqlalchemy.sql.expression import select

import common.db.postgres as db
from common.apikey import require_api_key
from common.db.model.status_list import CredentialStatusList
from common.status_list import StatusListRegistryData
from common.model import ietf
import common.model.registry.communication as comms
import common.model.exception as ex
from common.fastapi_extensions import ExtendedFastAPI

import registry_revocation.config as conf
from registry_revocation.route.health import router as health_router

#################
# DB Definition #
#################

_logger = logging.getLogger(__name__)

app = ExtendedFastAPI(conf.inject)

app.add_middleware(CorrelationIdMiddleware)
#################
# REST Endpoint #
#################

router = APIRouter(prefix="/issuer/{issuer_id}", responses={status.HTTP_404_NOT_FOUND: {"model": ex.HTTPError}})


def verify_vc(
    status_list: CredentialStatusList,
    issuer_update_jwt: comms.UpdateJWT,
    config: conf.RevocationRegistryConfig,
) -> tuple[dict]:
    """
    Loads the issuer and verify the request jwt
    Will update the issuer nonce
    Returns the issuer and the claims of the jwt
    """
    public_key_set_url = f"{config.registry_key_url}/issuer/{status_list.issuer_id}/.well-known/jwks.json"
    try:
        response = httpx.get(
            public_key_set_url,
            verify=config.enable_ssl_verification,
        )
        response.raise_for_status()
        jwks = ietf.JSONWebKeySet.model_validate(response.json())
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Can not load public key set: {public_key_set_url}",
        )
    try:
        claims = issuer_update_jwt.extract_claims(jwks)
        comms.verify_subject(str(status_list.issuer_id), claims)
        comms.verify_nonce(str(status_list.nonce), claims)
    except comms.VerificationError as e:
        _logger.exception("Received an invalid JWT")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=e.detail)
    except Exception:
        _logger.exception("Received an unparsable JWT")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="JWT could not be decoded / validated")

    return claims


@router.get("/status-list")
def list_issuer_status_lists(issuer_id: uuid.UUID, session: db.inject) -> list[uuid.UUID]:
    status_lists = session.execute(select(CredentialStatusList.id).where(CredentialStatusList.issuer_id == issuer_id)).all()
    return list(map(lambda sl: sl[0], status_lists))


@router.get("/status-list/{status_list_id}")
def get_status_list(issuer_id: uuid.UUID, status_list_id: uuid.UUID, session: db.inject) -> str:
    """
    Returns the Statuslist VC as a JWT
    """
    res = session.execute(select(CredentialStatusList.status_credential_jwt).where(CredentialStatusList.issuer_id == issuer_id, CredentialStatusList.id == status_list_id)).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="issuer_id / status_list_id combination not found")
    return res[0]


@router.patch(
    "/status-list/{status_list_id}",
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized - Issue with Update JWT", "model": ex.HTTPError}},
    dependencies=[Security(require_api_key)],
)
def update_status_list(
    issuer_id: uuid.UUID,
    status_list_id: uuid.UUID,
    issuer_update_jwt: comms.UpdateJWT,
    session: db.inject,
    config: conf.inject,
) -> StatusListRegistryData:
    status_list: CredentialStatusList = session.execute(
        select(CredentialStatusList).where(CredentialStatusList.issuer_id == issuer_id, CredentialStatusList.id == status_list_id)
    ).first()[0]
    claims = verify_vc(status_list, issuer_update_jwt, config)
    # Update Nonce for the next update
    status_list.nonce = uuid.uuid4()
    status_list.status_credential_jwt = claims['jwt_vc']
    session.add(status_list)
    session.flush()
    session.commit()
    session.refresh(status_list)
    return status_list


@router.get("/status-list/{status_list_id}/nonce")
def get_status_list_nonce(issuer_id: uuid.UUID, status_list_id: uuid.UUID, session: db.inject) -> uuid.UUID:
    """
    The nonce required by the issuer to update the status list
    """
    res = session.execute(select(CredentialStatusList.nonce).where(CredentialStatusList.issuer_id == issuer_id, CredentialStatusList.id == status_list_id)).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="issuer_id / status_list_id combination not found")
    return res[0]


app.include_router(router)


#############
#  Health   #
#############

app.include_router(health_router)
