# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
import datetime
import json

from fastapi import HTTPException, status
import httpx as req
import sqlalchemy.exc

import common.key_configuration as key
from common import verifiable_credential as vc
import common.db.postgres as db
import common.status_list as sl

import issuer.models
import issuer.config as conf
import issuer.db.status_list as sl_db


_logger = logging.getLogger(__name__)


def create_issuer_jwt(config: conf.IssuerConfig, key_conf: key.KeyConfiguration, payload: dict, nonce=None) -> str:
    """
    JWT Signed by the issuer; for a very simplistic VC
    """
    # TODO -> EID-1249: Consider how to remove this and use the VC Builder instead?
    # Create JWT
    # Data to identify towards base registry
    body_data = {'iss': f'{config.get_key_registry_uri()}', 'sub': config.issuer_id}
    if nonce:
        body_data['nonce'] = nonce
    body_data.update(payload)
    update_jwt = key_conf.encode_jwt(body_data)
    return update_jwt


def create_issuer_update_jwt(config: conf.IssuerConfig, key_conf: key.KeyConfiguration, payload: dict, nonce=None) -> str:
    """
    Creates a JWT as required for communication and verification with the base registry services
    """
    data = json.dumps({"update_jwt": create_issuer_jwt(config=config, key_conf=key_conf, payload=payload, nonce=nonce)})
    return data


def get_registry_nonce(uri, config: conf.IssuerConfig):
    try:
        r = req.get(uri, verify=config.enable_ssl_verification)
        if r.status_code != 200:
            raise HTTPException(status_code=r.status_code, detail=f"Registry Message: {r.json()}")
        nonce = r.json()
    except Exception:
        msg = f"Registry '{uri}' can not be reached"
        _logger.exception(msg)
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=msg)
    return nonce


def get_registry_status_list_nonce(purpose: str, config: conf.IssuerConfig):
    return get_registry_nonce(f'{config.get_status_list_uri(purpose)}/nonce', config)


def create_status_list_issuer_jwt(status_list_uri: str, status_list: sl.StatusList2021, purpose: str, config: conf.IssuerConfig, key_conf: key.KeyConfiguration):
    """
    Creates a status list vc from the current configuration
    Fetches the current nonce from the base registry
    """
    status_list_vc = {
        "@context": ["https://www.w3.org/ns/credentials/v2", "https://w3id.org/vc/status-list/2021/v1"],
        "id": f"{status_list_uri}",
        "type": ["VerifiableCredential", "StatusList2021Credential"],
        "issuer": f'{config.get_key_registry_uri()}',
        "validFrom": datetime.datetime.now().isoformat(),
        "credentialSubject": {"id": f"{status_list_uri}#list", "type": "StatusList2021", "statusPurpose": purpose, "encodedList": status_list.pack()},
    }
    status_list_jwt = create_issuer_jwt(config=config, key_conf=key_conf, payload={'vc': status_list_vc})
    data = create_issuer_update_jwt(config=config, key_conf=key_conf, payload={'jwt_vc': status_list_jwt}, nonce=get_registry_status_list_nonce(purpose, config=config))
    return data


REQUEST_HEADER_JSON = {'accept': 'application/json', 'Content-Type': 'application/json'}


def update_status_list_index(index: int, value: bool, purpose: str, session, config: conf.IssuerConfig, key_conf: key.KeyConfiguration) -> sl.StatusListRegistryData:
    # TODO -> EID-1251: Make Selectable status list instead of config
    db_sl = sl_db.get_status_list_orm(config.status_list_map[purpose], session)
    status_list = sl.from_string(db_sl.data_zip)
    status_list.set_bit(index, value)
    status_list_uri = config.get_status_list_uri(purpose)
    statuslist_jwt = create_status_list_issuer_jwt(status_list_uri, status_list=status_list, purpose=purpose, config=config, key_conf=key_conf)
    try:
        r = config.get_revocation_registry_client().patch(
            status_list_uri,
            data=statuslist_jwt,
            headers=REQUEST_HEADER_JSON,
        )
        assert r.status_code == 200
    except Exception:
        raise HTTPException(status_code=r.status_code, detail=r.text)

    db_sl.data_zip = status_list.pack()
    try:
        updated_status_list = r.json()
        return sl.StatusListRegistryData.model_validate(updated_status_list)
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to update status list {e}")


def get_registry_base_nonce(config: conf.IssuerConfig):
    return get_registry_nonce(f'{config.get_key_registry_uri()}/nonce', config)


def open_status_lists(config: conf.IssuerConfig, session: db.Session) -> dict[str, sl.StatusList2021]:
    """
    Loads or creates a status list for each configured purpose
    Returns a dictionary with "purpose": StatusList
    """

    def open_status_list(conf: issuer.models.StatusListConfiguration) -> tuple[str, sl.StatusList2021]:
        try:
            status_list = sl_db.get_status_list(session=session, status_list_id=conf.status_list_id)
        except sqlalchemy.exc.NoResultFound:
            status_list = sl_db.create_status_list(session=session, issuer_id=config.issuer_id, status_list_id=conf.status_list_id, purpose=conf.purpose)
        return conf.purpose, status_list

    return dict(map(open_status_list, config.status_list_config))


def create_credential_status(session, config: conf.IssuerConfig, purpose: str) -> dict:
    """
    Creates a StatusList Entry for a VC
    """
    index = sl_db.use_statuslist_index(config.status_list_map[purpose], session=session)
    # TODO -> EID-1250: Use pydantic model
    status = {
        # Where to find the Statuslist
        'id': f'{config.get_status_list_uri(purpose)}#{index}',
        'type': 'StatusList2021Entry',
        'statusPurpose': purpose,
        'statusListIndex': index,
        # The credential the statuslist is signed with
        'statusListCredential': f'{config.get_key_registry_uri()}',
    }

    return status
