# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid

import fastapi
from fastapi import HTTPException, status
from common.apikey import require_api_key

import common.db.postgres as db
import common.key_configuration as key
import common.credential_offer as co
import common.model.exception as ex

import issuer.config as conf
import issuer.credential_offer as offer
import issuer.statuslist2021 as sl_2021
import issuer.db.credential as db_credential
from issuer.models import VcManagementInfo
from common.key_configuration import KeyConfiguration
from common import parsing

TAG = "Credential Management"


router = fastapi.APIRouter(prefix="/oid4vc/credential", dependencies=[fastapi.Security(require_api_key)], tags=[TAG])


@router.post("/offer")
def create_generic_offer(data: co.CredentialOfferData, config: conf.inject, session: db.inject) -> co.CredentialOfferResponse:
    """
    Endpoint for creating an offer for a single credential
    """
    return offer.create_credential_offer(data, config, session)


def load_management_object(credential_management_id: uuid.UUID, session: db.inject) -> db_credential.CredentialManagement:
    management = db_credential.get_management_object(session=session, management_id=credential_management_id)
    if not management:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"No Credential with {credential_management_id=}")
    return management


@router.get("/{credential_management_id}/offer_data", description="Gets the offer data, if any is still cached")
def get_credential_management_data(credential_management_id: uuid.UUID, session: db.inject) -> dict:
    management = load_management_object(credential_management_id, session)
    return management.credential_offer.offer_data


@router.get("/{credential_management_id}/offer_deeplink")
def get_credential_management_deeplink(credential_management_id: uuid.UUID, config: conf.inject, session: db.inject) -> str:
    credential_offer = load_management_object(credential_management_id, session).credential_offer
    return offer.create_preauthorized_offer_link(
        metadata_credential_supported_ids=[credential_offer.metadata_credential_supported_id],
        pre_auth_code=str(credential_offer.id),
        external_url=config.external_url,
        pin_required=bool(credential_offer.pin),
    )


@router.get(
    "/{credential_management_id}/offer_deeplink/short",
    description="Returns a short version of the deeplink for easier displaying",
)
def get_short_deeplink(credential_management_id: uuid.UUID, config: conf.inject, session: db.inject) -> str:
    credential_offer = load_management_object(credential_management_id, session).credential_offer
    offer_id_short = parsing.remove_padding(parsing.uuid_to_url_safe(credential_offer.id))
    return f"{config.external_url}/offer/{offer_id_short}"


@router.get("/{credential_management_id}/status")
def get_credential_management_status(credential_management_id: uuid.UUID, session: db.inject) -> str:
    management = load_management_object(credential_management_id, session)
    return management.credential_status


def _update_credential_status_for_unprocessed_vcs(management: db_credential.CredentialManagement, revoke_credential: bool):
    assert not db_credential.CredentialStatus.is_post_holder_interaction(management.credential_status), "Implementation error. This method can only handle uncommited offers."

    if revoke_credential:
        management.credential_status = db_credential.CredentialStatus.REVOKED.value
        # Delete Buffered VC Data
        management.credential_offer.offer_data = {}


def _update_credential_status_for_processed_vcs(
    session: db.Session, config: conf.IssuerConfig, key_conf: KeyConfiguration, management: db_credential.CredentialManagement, credential_status: bool, purpose: str
):
    # Get the correct status list according purpose
    status_list_associations = [association for association in management.status_list_associations if association.status_list.purpose == purpose]

    if not status_list_associations:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Credential {management.id} does not have a status for {purpose}")

    current_status = db_credential.CredentialStatus(management.credential_status)
    purpose_status = db_credential.CredentialStatus.purpose_to_status(purpose)

    if (current_status == purpose_status and credential_status) or current_status == db_credential.CredentialStatus.REVOKED:
        # Status already set or credential already revoked - There should be no change.
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Tried to set {purpose} but status is already {management.credential_status}")

    # Update Statulist VC
    # TODO -> EID-1255: Handle having the credential on a different status list than the currently used one
    sl_2021.update_status_list_index(
        index=int(status_list_associations[0].status_list_index), value=credential_status, purpose=purpose, session=session, config=config, key_conf=key_conf
    )

    # Update Status
    if purpose_status and (current_status == db_credential.CredentialStatus.ISSUED or purpose_status == db_credential.CredentialStatus.REVOKED):
        # Set the status
        management.credential_status = purpose_status.value
    elif current_status == purpose_status:
        # Reset the Issued
        management.credential_status = db_credential.CredentialStatus.ISSUED.value


def _reset_offer(management: db_credential.CredentialManagement):
    """Resets the credential offer"""
    management.credential_status = db_credential.CredentialStatus.OFFERED.value


@router.patch(
    "/{credential_management_id}/status",
    responses={
        200: {
            "description": "Status has been changed. VC info is returned",
            "model": VcManagementInfo,
        },
        400: {
            "description": "Status is already the given value.",
            "model": ex.HTTPError,
        },
    },
    description="""
    Updates the statuslist with the purpose for the given credential


    * credential_management_id: The ID of the credential to be updated
    * purpose: The purpose of the status list for the status to be updated
    * credential_status: true to set the status within the purpose, flase to unset it.
    """,
)
def update_credential_status(
    session: db.inject,
    config: conf.inject,
    key_conf: key.inject,
    credential_management_id: uuid.UUID,
    purpose: str,
    credential_status: bool = True,
):
    """
    Updates the credential status of the managed credential
    """
    management = load_management_object(credential_management_id, session)
    if db_credential.CredentialStatus.is_post_holder_interaction(management.credential_status):
        _update_credential_status_for_processed_vcs(
            session=session, config=config, key_conf=key_conf, management=management, credential_status=credential_status, purpose=purpose.lower()
        )
    elif db_credential.CredentialStatus.is_during_holder_interaction(management.credential_status):
        _reset_offer(management)
    else:
        _update_credential_status_for_unprocessed_vcs(management, credential_status)

    session.commit()
    return VcManagementInfo.model_validate(management, from_attributes=True)
