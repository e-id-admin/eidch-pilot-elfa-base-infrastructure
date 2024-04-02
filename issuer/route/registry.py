# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Operations with the registry, including statuslist
"""

from fastapi import APIRouter, HTTPException, Security
from fastapi.responses import Response

# Sending HTTP Requests
import httpx as req

from common.apikey import require_api_key
import common.db.postgres as db
import common.key_configuration as key

import issuer.config as conf
import issuer.models as model
import issuer.statuslist2021 as sl_2021

router = APIRouter(prefix='/admin', dependencies=[Security(require_api_key)])

TAG_REGISTRY = "Registry Operations"
TAG_STATUSLIST = "Statuslist2021"


@router.get("/issuer_id", description="Returns the ID the issuer has configured - has to exist in the base registry", tags=[TAG_REGISTRY])
def get_issuer_id(config: conf.inject) -> str:
    return config.issuer_id


@router.get("/status-list", description="Returns the ID the issuer uses in the revocation registry", tags=[TAG_REGISTRY])
def get_status_list_id(config: conf.inject) -> list[model.StatusListConfiguration]:
    return config.status_list_config


@router.get(
    "/liveness",
    description="Returns if configuration could be loaded and the database connection be established.",
    tags=[TAG_REGISTRY],
    responses={200: {}, 500: {}},
)
def get_liveness(config: conf.inject, session: db.inject) -> None:
    liveness = config.db_connection is not None and session.is_active
    return Response(status_code=200) if liveness else Response(status_code=500)


@router.get(
    "/readiness",
    description="Returns if the service seems ready accept connections",
    tags=[TAG_REGISTRY],
    responses={200: {}, 500: {}},
)
def get_readiness(config: conf.inject, session: db.inject, key_config: key.inject) -> None:
    # Configurations set
    config_settings = all(
        [
            config.db_connection,
            config.api_key,
            config.external_url,
            config.registry_key_url,
            config.registry_revocation_url,
        ]
    )

    readiness = all([key_config.jwk_did, config_settings, session.is_active])
    return Response(status_code=200) if readiness else Response(status_code=500)


@router.patch("/status-list", description="Updates the status list on the registry with the local status list", tags=[TAG_REGISTRY])
def update_statuslist(config: conf.inject, session: db.inject, key_conf: key.inject):
    # TODO -> EID-1258: Expand to Status List Controll Interface (Change Size of status list, set purpose, initialize, etc...)
    # Create VC for StatusList
    status_list_map = sl_2021.open_status_lists(config, session)
    for purpose, status_list in status_list_map.items():
        status_list_uri = config.get_status_list_uri(purpose)
        statuslist_jwt = sl_2021.create_status_list_issuer_jwt(status_list_uri, status_list=status_list, purpose=purpose, config=config, key_conf=key_conf)

        r = config.get_revocation_registry_client().patch(
            status_list_uri,
            data=statuslist_jwt,
            headers=sl_2021.REQUEST_HEADER_JSON,
        )

        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=r.text)


@router.patch("/update_keys", description="Updates the keys at the base register", tags=[TAG_REGISTRY])
def update_keys(config: conf.inject, key_conf: key.inject):
    # Fetch Nonce
    data = sl_2021.create_issuer_update_jwt(config=config, key_conf=key_conf, payload={"jwks": key_conf.jwks}, nonce=sl_2021.get_registry_base_nonce())
    r = config.get_base_registry_client().patch(
        f'{config.registry_key_url}/{config.issuer_id}',
        data=data,
    )
    return r.json()
