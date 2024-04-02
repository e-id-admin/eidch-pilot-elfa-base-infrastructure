# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import json
import logging
from typing import Annotated

# FastAPI
import fastapi
from fastapi import Response, status, Form

import pydantic

from verifier.models import AuthorizationResponseData
import verifier.models
import verifier.verification as ver
import verifier.exception.authorization_request_errors as ex
import verifier.exception.authorization_response_errors as openIdEx

import common.model.dif_presentation_exchange as dif
import common.verifiable_credential as vc
import verifier.cache.verifier_cache as cache
import verifier.config as conf

TAG = "OpenID"

_logger = logging.getLogger(__name__)

router = fastapi.APIRouter(tags=[TAG])

@router.get(
    "/liveness",
    description="Returns is server is alive.",
    responses={204: {"model": None}},
)
def get_liveness() -> None:
    return fastapi.Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get(
    "/readiness",
    description="Returns if server is alive and configuration is present.",
    responses={204: {"model": None}, 500: {"model": None}},
)
def get_readiness(config: conf.inject) -> None:
    return fastapi.Response(status_code=status.HTTP_204_NO_CONTENT if config.has_minimum_config() else status.HTTP_500_INTERNAL_SERVER_ERROR)


@router.get(
    "/health",
    description="Returns if server is alive and configuration is present.",
    responses={204: {"model": None}, 500: {"model": None}},
)
def health(config: conf.inject) -> None:
    is_healthy = all(
        [
            config.has_minimum_config(),
            cache.request_object_service,
            cache.verification_management_service,
            cache.presentation_definition_service,
            cache.authorization_response_data_service,
        ]
    )
    return fastapi.Response(status_code=status.HTTP_204_NO_CONTENT if is_healthy else status.HTTP_500_INTERNAL_SERVER_ERROR)

@router.get("/presentation-definition/{presentation_definition_id}", responses={status.HTTP_404_NOT_FOUND: {"model": openIdEx.OpenIdError}})
def get_presentation_definition(presentation_definition_id: str) -> dif.PresentationDefinition:
    if not cache.presentation_definition_service.exists(presentation_definition_id):
        raise ex.PresentationDefinitionNotFoundError()

    return cache.presentation_definition_service.get(presentation_definition_id)


@router.get("/request-object/{request_object_id}", responses={status.HTTP_404_NOT_FOUND: {"model": openIdEx.OpenIdError}}, response_model_exclude_none=True)
def get_request_object(request_object_id: str) -> dif.RequestObject:
    """
    Returns the Request Object.
    https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#name-overview (2)
    https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#name-authorization-request

    The ID is used to identify the proof invitation.
    """

    if not cache.request_object_service.exists(request_object_id):
        raise ex.AuthorizationRequestObjectNotFoundError()

    return cache.request_object_service.get(request_object_id).to_OpendIDRequestObject()


def process_error_response(config: conf.VerifierConfig, request_object_id: str, error: str, error_description: str = None) -> int:
    """Holder can send an error instead of a presentation. The error is shared with the verifier and the verification set to failed."""
    authorization_response_data = AuthorizationResponseData(error_code=error, error_description=error_description)
    authorization_response_data.set_expires_at(config.verification_ttl)
    cache.authorization_response_data_service.set(authorization_response_data, request_object_id)
    cache.verification_management_service.set_verification_status(
        expiresAt=config.verification_ttl, authorization_request_id=request_object_id, status=verifier.models.VerificationStatus.FAILED
    )
    return status.HTTP_200_OK


# TODO -> EID-1187: Change jwt from body to request parameter as with https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#appendix-A.1.2.3
# presentation_submission:str, vp_token:str
# TODO -> EID-1232: Handle "error", "error_description" and "error_uri" parameter as defined under https://www.rfc-editor.org/rfc/rfc6749.html#section-4.1.2.1 which may be returned from the holder app
# Additional "error" values ares described in OpenID4VP https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4
@router.post(
    "/request-object/{request_object_id}/response-data",
    description="""Processes all response-data of the holder for a verification(vp_token and DIF presentation submission) and updated the verification status accordingly.
    If there is a technical difficulty the error should be set to a fitting error response of https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.4
    If the client rejects the verification, the error should be set to client_rejected
    """,
)
def verify_presentation(
    config: conf.inject,
    response: Response,
    request_object_id: str,
    presentation_submission: Annotated[str | None, Form()] = None,
    vp_token: Annotated[str | None, Form()] = None,
    error: Annotated[str | None, Form()] = None,
    error_description: Annotated[str | None, Form()] = None,
):
    """
    Verifies the VC presentation.
    https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#section-6.1
    """

    if not cache.request_object_service.exists(request_object_id):
        raise ex.AuthorizationRequestObjectNotFoundError()
    if error:
        response = process_error_response(config, request_object_id, error, error_description)
        return response

    if not presentation_submission and not vp_token:
        raise ex.AuthorizationRequestMissingError()

    request_object = cache.request_object_service.get(request_object_id)
    verification_management = cache.verification_management_service.get_verification_management_by_request(request_object_id)
    if verification_management.status != verifier.models.VerificationStatus.PENDING:
        # The Verification has already been done before!
        raise ex.VerificationProcessClosed(additional_error_description=f"Status is already {verification_management.status.name}")

    try:
        presentation_response = vc.OpenID4VerifiablePresentationResponse(vp_token=vp_token, presentation_submission=json.loads(presentation_submission))
        return ver.verify_presentation(request_object, presentation_response, config)

    except json.decoder.JSONDecodeError as e:
        raise ex.InvalidPresentationDefinitionError(additional_error_description=f"JSON Decode Error: {e.msg} - Error at line {e.lineno} column {e.colno}")
    except pydantic.ValidationError as e:
        raise ex.InvalidPresentationDefinitionError(additional_error_description=e.json())
    except ex.OpenIdVerificationError as e:
        raise e
    except Exception as e:
        _logger.exception("InvalidPresentationDefinitionError")
        raise ex.InvalidPresentationDefinitionError(additional_error_description=str(e.args))
