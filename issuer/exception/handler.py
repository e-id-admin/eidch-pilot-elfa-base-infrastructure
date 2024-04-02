# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from fastapi import Request, FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError

from .credential_error_responses import OpenIdIssuanceException, InvalidRequestException


def configure_exception_handlers(app: FastAPI) -> None:
    """
    Configure exception handlers on the FastAPI app instance to conform to OID4VCI Standard.
    Changed 422 Unprocessable Entity to 400 Bad Request

    Args:
        app (FastAPI): the instance to configure the handlers for.
    """

    @app.exception_handler(OpenIdIssuanceException)
    async def openid_issuance_exception_handler(request: Request, exc: OpenIdIssuanceException):
        # Create a resonse based on the configured fields
        content_builder = {}

        # Include all required fields
        for field_name in exc._fields:
            content_builder[field_name] = getattr(exc, field_name)

        # Include all optional fields with a value which is not None
        for field_name in exc._optional_fields:
            if hasattr(exc, field_name) and getattr(exc, field_name) is not None:
                content_builder[field_name] = getattr(exc, field_name)

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
        wrapper_exception = InvalidRequestException()

        wrapper_exception.error_description += f" Details: {exc.errors()}"

        return await openid_issuance_exception_handler(request, wrapper_exception)
