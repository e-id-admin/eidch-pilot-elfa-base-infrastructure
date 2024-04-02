# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import json
import logging

from fastapi import APIRouter, Request, HTTPException, status, Security
from asgi_correlation_id import CorrelationIdMiddleware

from sqlalchemy.orm import Session
from sqlalchemy.sql.expression import select
import pydantic

import common.db.postgres as db
from common.apikey import require_api_key
from common.db.model.public_key import TrustedIssuer
import common.model.ietf as ietf
from common.model.registry.public_key import PublicKeyRegistryData
import common.model.registry.communication as comms
import common.model.exception as ex
from common.fastapi_extensions import ExtendedFastAPI
from common.health import HealthAPIRouterWithDBInject

from registry_base import config as conf

_logger = logging.getLogger(__name__)

#################
# DB Definition #
#################

app = ExtendedFastAPI(conf.inject)

app.add_middleware(CorrelationIdMiddleware)


registry_route = APIRouter()
#################
# REST Endpoint #
#################


##########
# Issuer #
##########
@registry_route.get("/issuers", description="Lists all registered issuers")
def get_issuers(session: db.inject) -> list[str]:
    issuers = session.execute(select(TrustedIssuer.id))
    return list(map(str, map(lambda i: i[0], issuers)))


issuer_router = APIRouter(prefix="/issuer/{issuer_id}", responses={status.HTTP_404_NOT_FOUND: {"model": ex.HTTPError, "description": "Issuer not found"}})


# We exclude_none to not have added in all optional parameters (like x5u for X.509 URL when we're using EC)
@issuer_router.get("", response_model_exclude_none=True)
def get_issuer_by_id(issuer_id: uuid.UUID, session: db.inject) -> PublicKeyRegistryData:
    res = session.execute(select(TrustedIssuer).where(TrustedIssuer.id == issuer_id)).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="issuer_id not found")
    issuer = res[0]
    return issuer


@issuer_router.get("/nonce", description="Nonce to be included as claim in the update JWT")
def get_issuer_nonce(issuer_id: uuid.UUID, session: db.inject) -> uuid.UUID:
    res = session.execute(select(TrustedIssuer.nonce).where(TrustedIssuer.id == issuer_id)).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="issuer_id not found")
    issuer_nonce: uuid.UUID = res[0]
    return issuer_nonce


def get_authorized_issuer(issuer_id: uuid.UUID, issuer_update_jwt: comms.UpdateJWT, session: Session) -> tuple[TrustedIssuer, dict]:
    """
    Loads the issuer and verify the update jwt.
    Will update the issuer nonce once the validity of the jwt was confirmed.
    Returns the issuer and the claims of the jwt.
    Raises Unauthorized HTTP Exception if jwt signature mismatch.
    """
    issuer: TrustedIssuer = session.execute(select(TrustedIssuer).where(TrustedIssuer.id == issuer_id)).first()[0]
    jwks = ietf.JSONWebKeySet.model_validate(issuer.public_key_set)
    # Verify JWT
    try:
        claims = issuer_update_jwt.extract_claims(jwks)
        comms.verify_subject(str(issuer_id), claims)
        issuer_nonce = get_issuer_nonce(issuer_id=issuer_id, session=session)
        comms.verify_nonce(str(issuer_nonce), claims)
    except comms.VerificationError as e:
        _logger.exception("Received an invalid JWT")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail=e.detail)
    except Exception:
        _logger.exception("Received an unparsable JWT")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="JWT could not be decoded / validated")
    # Update Issuer Nonce
    issuer.nonce = uuid.uuid4()
    session.add(issuer)

    return issuer, claims


@issuer_router.patch(
    "",
    description="""
    Endpoint for Issuers to update their information (eg. Key rotation). 
    Authentication via jwt signed by one of the keys.
    Requires in the claims of the update_jwt
    * sub
    * nonce
    * jwks
    """,
    responses={status.HTTP_401_UNAUTHORIZED: {"description": "Unauthorized - Issue with Update JWT", "model": ex.HTTPError}},
    dependencies=[Security(require_api_key)],
)
def update_issuer_keys(issuer_id: uuid.UUID, issuer_update_jwt: comms.UpdateJWT, session: db.inject):
    issuer, claims = get_authorized_issuer(issuer_id, issuer_update_jwt, session)
    # Update Keys
    if 'jwks' not in claims:
        raise HTTPException(status_code=400, detail="Missing JWKS, can not update keys")
    try:
        valideted_jwks = ietf.JSONWebKeySet.model_validate(claims['jwks'])
    except pydantic.ValidationError as e:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail=e.errors())
    issuer.public_key_set = valideted_jwks.model_dump()
    _logger.info(f"Updating {str(issuer_id)} to {json.dumps(issuer.public_key_set)}")
    issuer.nonce = uuid.uuid4()
    session.add(issuer)
    session.flush()
    session.commit()
    session.refresh(issuer)
    return issuer


##########
# OpenID #
##########


@issuer_router.get("/.well-known/jwks.json", response_model_exclude_none=True)
def get_issuer_jwks(issuer_id: uuid.UUID, session: db.inject) -> ietf.JSONWebKeySet:
    res = session.execute(select(TrustedIssuer.public_key_set).where(TrustedIssuer.id == issuer_id)).first()
    if not res:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="issuer_id not found")
    return res[0]


# TODO -> EID-1241: Consider if this is rquired & if yes, provide an interface for the issuer to set the data
@issuer_router.get("/.well-known/openid-configuration")
def get_openid_configuration(request: Request, config: conf.inject, issuer_id: uuid.UUID):
    scheme = 'https' if config.use_https else request.url.scheme
    uri = f'{scheme}://{request.url.hostname}'
    if request.url.port:
        uri = f'{uri}:{request.url.port}'
    return {'issuer': str(issuer_id), 'jwks_uri': f'{uri}/issuer/{str(issuer_id)}/.well-known/jwks.json'}


app.include_router(registry_route)
app.include_router(issuer_router)


#############
#  Health   #
#############

app.include_router(HealthAPIRouterWithDBInject())
