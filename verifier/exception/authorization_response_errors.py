# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
The verifier generates the authorizuation request object (as defined in (JAR) [RFC9101]) and makes it accessible
to the verifier. This file contains the authorization response error as defined in [RFC6794]
"""
from fastapi import HTTPException
from pydantic import BaseModel


class OpenIdError(BaseModel):
    """
    Error Class as defined in OpenID4VC/RFC 6749 standard.
    * error: Machine readable code identifying the exception
    * error_description: Human readable error description of the error to help the developer

    Custom added in Fields (see https://confluence.bit.admin.ch/display/EIDTEAM/Evaluation+OIDC+for+VC)
    * error_code: Machine readable code further specifying the error
    * additional_error_description: Further human readable information on the error
    """

    error: str
    error_description: str
    error_code: str | None = None
    additional_error_description: str | None = None


class OpenIdVerificationError(HTTPException):
    """Base class for all openid verification exceptions."""

    error: str = None
    """Machine readable code identifieng the exception."""

    error_description: str = None
    """Human readable error description for the error type."""

    _fields: list[str] = [
        "error",
        "error_description",
    ]
    """Fields to render into the response."""

    _optional_fields: list[str] = ["additional_error_description"]
    """Optional fiels which only get renderd into the response if available."""

    def __init__(self, status_code: int = 400, additional_error_description: str = None) -> None:
        """Create a OpenId issuance exception.

        Args:
            status_code (int, optional):  status code for the rendered response. Defaults to 400.
            additional_error_description (str, optional): Additional, human readable data, to identify the issue resulting in this exception.
        """
        super().__init__(status_code, self.error, headers={"Cache-Control": "no-store"})
        # Assignfrom the class definition to the instance
        self.additional_error_description = additional_error_description


class UnauthorizedClientError(OpenIdVerificationError):
    """The client is not authorized to request an authorization code using this method."""

    error = "unauthorized_client"
    error_description = "The client is not authorized to request an authorization code using this method."


class AccessDeniedError(OpenIdVerificationError):
    """The resource owner or authorization server denied the request."""

    error = "access_denied"
    error_description = "The resource owner or authorization server denied the request."

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(403, additional_error_description)


class UnsupportedResponseTypeError(OpenIdVerificationError):
    """The authorization server does not support obtaining an authorization code using this method."""

    error = "unsupported_response_type"
    error_description = "The authorization server does not support obtaining an authorization code using this method."


class InvalidScopeError(OpenIdVerificationError):
    """The client is not authorized to request an authorization code using this method."""

    error = "invalid_scope"
    error_description = "The requested scope is invalid, unknown, or malformed"


class InvalidRequestError(OpenIdVerificationError):
    """The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."""

    error = "invalid_request"
    error_description = "The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."

    def __init__(self, status_code: int = 400, authorization_request_id: str = None, additional_error_description: str = None) -> None:
        super().__init__(status_code, additional_error_description)
        self.authorization_request_id = authorization_request_id
