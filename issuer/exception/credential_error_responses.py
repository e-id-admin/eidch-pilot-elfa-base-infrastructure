# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
The issuance process does describe certain error in the process which we want to support here.
See https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.3.1 for OID4VCI
and https://www.rfc-editor.org/rfc/rfc6750#section-3.1 for OAuth2.0
"""

from fastapi import HTTPException
from pydantic import BaseModel


class OpenIdError(BaseModel):
    """
    Error Class as defined in OpenID4VC standard.
    * error: Machine readable code identifieng the exception
    * error_description: Human readable error description for the error type.
    """

    error: str
    error_description: str


class OpenIdErrorNonce(OpenIdError):
    """
    OpenId Error class providing a new nonce to be used in the next request
    * error: Machine readable code identifieng the exception
    * error_description: Human readable error description for the error type.
    * c_nonce: The c_nonce to be used in the proof
    * c_nonce_expires_in: Validity of the c_nonce
    """

    c_nonce: str
    c_nonce_expires_in: int


class OpenIdIssuanceException(HTTPException):
    """Base class for all openid issuance exceptions."""

    error: str = None
    """Machine readable code identifieng the exception."""

    error_description: str = None
    """Human readable error description for the error type."""

    _fields: list[str] = [
        "error",
        "error_description",
    ]
    """Fields to render into the response."""

    _optional_fields: list[str] = []
    """Optional fiels which only get renderd into the response if available."""

    def __init__(self, status_code: int = 400, additional_error_description: str = None) -> None:
        """Create a OpenId issuance exception.

        Args:
            status_code (int, optional):  status code for the rendered response. Defaults to 400.
            additional_error_description (str, optional): Additional, human readable data, to identify the issue resulting in this exception.
        """
        super().__init__(status_code, self.error, headers={"Cache-Control": "no-store"})

        if additional_error_description:
            self.error_description = f"{self.error_description} {additional_error_description}"


class InsufficientScopeException(OpenIdIssuanceException):
    """
    The request requires higher privileges than provided by the access token.
    OAuth 2.0 Exception
    """

    error = "insufficient_scope"
    error_description = "The request requires higher privileges than provided by the access token."

    def __init__(self, scope: str = None, additional_error_description: str = None) -> None:
        super().__init__(403, additional_error_description)
        self.scope = scope
        self._optional_fields += ["scope"]


class InvalidRequestException(OpenIdIssuanceException):
    """Credential Request was malformed. One or more of the parameters (i.e. format, proof) are missing or malformed."""

    error = "invalid_request"
    error_description = "Credential Request was malformed. One or more of the parameters (i.e. format, proof) are missing or malformed."


class InvalidGrantException(OpenIdIssuanceException):
    """
    https://datatracker.ietf.org/doc/html/rfc6749#section-5.2
    * the Authorization Server expects a PIN in the pre-authorized flow but the client provides the wrong PIN
    * the End-User provides the wrong Pre-Authorized Code or the Pre-Authorized Code has expired
    """

    error = "invalid_grant"
    error_description = "A wrong or expired Pre-Authorized Code was provided or the PIN was incorrect."


class InvalidTokenException(OpenIdIssuanceException):
    """
    Credential Request contains the wrong Access Token or the Access Token is missing.
    OAuth 2.0 Exception
    """

    error = "invalid_token"
    error_description = "Credential Request contains the wrong Access Token or the Access Token is missing."

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(401, additional_error_description)


class UnsupportedCredentialTypeException(OpenIdIssuanceException):
    """
    Requested credential type is not supported.
    OID4VCI Exception
    """

    error = "unsupported_credential_type"
    error_description = "Requested credential type is not supported."


class UnsupportedCredentialFormatException(OpenIdIssuanceException):
    """
    Requested credential format is not supported.
    OID4VCI Exception
    """

    error = "unsupported_credential_format"
    error_description = "Requested credential format is not supported."


class InvalidOrMissingProofException(OpenIdIssuanceException):
    """
    Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce.
    OID4VCI Exception
    """

    error = "invalid_or_missing_proof"
    error_description = "Credential Request did not contain a proof, or proof was invalid, i.e. it was not bound to a Credential Issuer provided nonce."

    c_nonce: str = None
    c_nonce_expires_in: int = None

    def __init__(self, additional_error_description: str = None, c_nonce: str = None, c_nonce_expires_in: int = None) -> None:
        super().__init__(additional_error_description)
        self.c_nonce = c_nonce
        self.c_nonce_expires_in = c_nonce_expires_in

        self._optional_fields = super()._optional_fields + [
            "c_nonce",
            "c_nonce_expires_in",
        ]
