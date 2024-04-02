# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from verifier.models import VerificationStatus
from verifier.models import AuthorizationResponseData
import verifier.cache.verifier_cache as cache
import verifier.config as config

from .authorization_response_errors import OpenIdVerificationError, InvalidRequestError
from .extended_authorization_response_errors import CodedInvalidRequestError


def configure_exception_handlers(app: FastAPI, config: config.VerifierConfig) -> None:
    """
    Configure exception handlers on the FastAPI app instance to conform to OID4VCI Standard.
    Changed 422 Unprocessable Entity to 400 Bad Request

    Args:
        app (FastAPI): the instance to configure the handlers for.
    """

    @app.exception_handler(OpenIdVerificationError)
    async def openid_issuance_exception_handler(request: Request, exc: OpenIdVerificationError):
        # Create a resonse based on the configured fields
        content_builder = {}

        # Include all required fields
        for field_name in exc._fields:
            content_builder[field_name] = getattr(exc, field_name)

        # Include all optional fields with a value which is not None
        for field_name in exc._optional_fields:
            if hasattr(exc, field_name) and getattr(exc, field_name) is not None:
                content_builder[field_name] = getattr(exc, field_name)

        if isinstance(exc, InvalidRequestError):
            # Updates the verification management and the request_response_data for the end-user so that the throwed error can be transmitted
            if exc.authorization_request_id:
                presentation_response = AuthorizationResponseData(error_description=exc.error_description, state=exc.authorization_request_id)
                presentation_response.set_expires_at(config.verification_ttl)
                if isinstance(exc, CodedInvalidRequestError):
                    presentation_response.error_code = exc.error_code
                cache.authorization_response_data_service.set(obj=presentation_response, id=exc.authorization_request_id)
                cache.verification_management_service.set_verification_status(
                    expiresAt=config.verification_ttl, authorization_request_id=exc.authorization_request_id, status=VerificationStatus.FAILED
                )
        logging.info(f"OID4VC Exception {exc.status_code=} {content_builder}")
        return JSONResponse(
            status_code=exc.status_code,
            headers=exc.headers,
            content=content_builder,
        )

    @app.exception_handler(RequestValidationError)
    async def openid_invalid_request_exception_handler(request: Request, exc: RequestValidationError):
        """
        Recasts Validation Errors to OpenID4VC conform exceptions
        """
        wrapper_exception = InvalidRequestError()

        wrapper_exception.error_description += f" Details: {exc.errors()}"

        return await openid_issuance_exception_handler(request, wrapper_exception)
