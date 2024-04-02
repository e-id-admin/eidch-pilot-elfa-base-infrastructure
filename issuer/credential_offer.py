# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import logging
import time
import urllib.parse

import common.db.postgres as db
import common.credential_offer as co
import common.verifiable_credential as vc

import issuer.db.credential as db_credential
import issuer.config as conf
from issuer.logging import IssuerOperationsLogEntry

_logger = logging.getLogger(__name__)


def create_preauthorized_offer_link(metadata_credential_supported_ids: list[str | dict], pre_auth_code: str, external_url: str, pin_required=False) -> str:
    """
    Creates a minimalist pre authorized credential offer according to
    https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters
    Note: The metadata_credential_supported_id are the credential ids as in the openid-credential-issuer
    """
    credential_offer = {
        "credential_issuer": external_url,
        "credentials": metadata_credential_supported_ids,
        "grants": {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code": pre_auth_code, "user_pin_required": pin_required}},
    }
    validated = vc.CredentialOfferParameters.model_validate(credential_offer)

    return f"openid-credential-offer://?credential_offer={urllib.parse.quote_plus(validated.model_dump_json(by_alias=True, exclude_none=True))}"


def create_credential_offer(data: co.CredentialOfferData, config: conf.IssuerConfig, session: db.Session) -> co.CredentialOfferResponse:
    """
    Creates a credential offer, registers it and creates a credential offer response
    """
    offer_id = uuid.uuid4()
    # TODO -> EID-1245: Check that metadata_credential_supported_id is actually mapped in the metadata, else the holder will get a 404 when fetching credentials
    offer = create_preauthorized_offer_link(
        metadata_credential_supported_ids=[data.metadata_credential_supported_id], pre_auth_code=str(offer_id), external_url=config.external_url, pin_required=bool(data.pin)
    )

    valid_from = data.credential_valid_from.isoformat() if data.credential_valid_from else None
    valid_until = data.credential_valid_until.isoformat() if data.credential_valid_until else None
    management_id = db_credential.register_offer(
        session=session,
        metadata_credential_supported_id=data.metadata_credential_supported_id,
        status_list_ids=list(config.status_list_map.values()),
        offer_id=offer_id,
        offer_data=data.credential_subject_data,
        pin=data.pin,
        offer_expiration_timestamp=round(time.time()) + data.offer_validity_seconds,
        valid_from=valid_from,
        valid_until=valid_until,
    )
    session.commit()
    _logger.info(
        IssuerOperationsLogEntry(
            message="Offer created.",
            status=IssuerOperationsLogEntry.Status.success,
            operation=IssuerOperationsLogEntry.Operation.issuance,
            step=IssuerOperationsLogEntry.Step.issuance_preparation,
            management_id=management_id,
        ),
    )
    return co.CredentialOfferResponse(management_id=management_id, offer_deeplink=offer)
