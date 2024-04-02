# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
import uuid

# FastAPI
import fastapi
from verifier.exception.authorization_response_errors import OpenIdError
import verifier.exception.verification_management_errors as err

import common.model.dif_presentation_exchange as dif
from common.apikey import require_api_key
from fastapi import status
import verifier.config as conf
import verifier.cache.verifier_cache as cache
import verifier.models as models

from verifier.logging import VerifierOperationsLogEntry

_logger = logging.getLogger(__name__)

TAG = "Verification Management"

router = fastapi.APIRouter(prefix="/oid4vp/verification", dependencies=[fastapi.Security(require_api_key)], tags=[TAG])


def create_authorization_request(presentation_definition_id: str, verifier_client_meta_data: dif.ClientMetadata, config: conf.inject) -> str:
    id = str(uuid.uuid4())
    authorize_request_object = models.VerificationRequestObject(
        presentation_definition=cache.presentation_definition_service.get(presentation_definition_id),
        nonce=uuid.uuid4().hex,
        response_mode="direct_post",
        id=id,
        response_uri=f"{config.verifier_url}/request-object/{id}/response-data",
        client_metadata=verifier_client_meta_data,
    )
    authorize_request_object.set_expires_at(config.verification_ttl)
    cache.request_object_service.set(authorize_request_object, id)
    return id


def create_verification_management(
    presentation_definition: models.PresentationDefinition, client_metadata: dif.ClientMetadata, config: conf.inject
) -> models.VerificationManagement:
    presentation_definition.set_expires_at(config.verification_ttl)
    cache.presentation_definition_service.set(presentation_definition, presentation_definition.id)
    authorization_request_id = create_authorization_request(presentation_definition.id, client_metadata, config)
    verification_management_id = str(uuid.uuid4())
    verification_management = models.VerificationManagement(
        status=models.VerificationStatus.PENDING,
        id=verification_management_id,
        authorization_request_id=authorization_request_id,
        authorization_request_object_uri=f"{config.verifier_url}/request-object/{authorization_request_id}",
    )
    verification_management.set_expires_at(config.verification_ttl)
    cache.verification_management_service.set(verification_management, verification_management_id)

    _logger.info(
        VerifierOperationsLogEntry(
            message="Requesting verification.",
            status=VerifierOperationsLogEntry.Status.success,
            operation=VerifierOperationsLogEntry.Operation.verification,
            step=VerifierOperationsLogEntry.Step.verification_request,
            management_id=verification_management_id,
        ),
    )

    return verification_management


@router.get("/{verification_management_id}", responses={status.HTTP_404_NOT_FOUND: {"model": OpenIdError}})
def get_verification(verification_management_id: str) -> models.VerificationManagement:
    if not cache.verification_management_service.exists(verification_management_id):
        raise err.VerificationNotFoundError(additional_error_description="test")
    return cache.verification_management_service.get(verification_management_id)


@router.get("/{verification_management_id}/response-data", description="Gets the submitted verification data of the holder. Currently all data are returned unprocessed")
def get_verification_data(verification_management_id: str) -> models.AuthorizationResponseData:
    if not cache.verification_management_service.exists(verification_management_id):
        raise err.VerificationNotFoundError()

    verification_management = cache.verification_management_service.get(verification_management_id)

    # Verification is not finished successfully or with an error
    if verification_management.status is models.VerificationStatus.PENDING:
        raise err.VerificationNotFinishedError()

    # TODO make this cleaner by using e.g. a expired_at property
    is_expired = verification_management.status is models.VerificationStatus.SUCCESS and not cache.authorization_response_data_service.exists(
        verification_management.authorization_request_id
    )
    if is_expired:
        _logger.info(
            VerifierOperationsLogEntry(
                message="Verification expired.",
                status=VerifierOperationsLogEntry.Status.error,
                operation=VerifierOperationsLogEntry.Operation.verification,
                step=VerifierOperationsLogEntry.Step.verification_response,
                management_id=verification_management_id,
                error_code=err.VerificationExpiredError.error,
            ),
        )
        raise err.VerificationExpiredError()

    if not cache.authorization_response_data_service.exists(verification_management.authorization_request_id):
        raise err.VerificationNotFinishedError()

    data = cache.authorization_response_data_service.get(verification_management.authorization_request_id)
    cache.authorization_response_data_service.remove(verification_management.authorization_request_id)
    _logger.info(
        VerifierOperationsLogEntry(
            message="Verification result delivered.",
            status=VerifierOperationsLogEntry.Status.success,
            operation=VerifierOperationsLogEntry.Operation.verification,
            step=VerifierOperationsLogEntry.Step.verification_response,
            management_id=verification_management_id,
        ),
    )
    return data


# TODO Create presentation definition in advance, to prevent persisiting unnecessary data
@router.post(path="", description="Creates an verification based on the handed DIF presentation definition")
def create_verification(presentation_definition: models.PresentationDefinitionRequest, config: conf.inject) -> models.VerificationManagement:
    return create_verification_management(
        models.PresentationDefinition(id=str(uuid.uuid4()), input_descriptors=presentation_definition.input_descriptors),
        client_metadata=presentation_definition.client_metadata,
        config=config,
    )
