# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
The verifier generates the authorizuation request object (as defined in (JAR) [RFC9101]) and makes it accessible
to the verifier. On top of the authorization request errors defined in [RFC6794] for the standardized argument
the following part defined the error for the authorization request params defined in
https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5-7
"""

from .authorization_response_errors import OpenIdVerificationError
from fastapi import status


class InvalidPresentationDefinitionError(OpenIdVerificationError):
    """The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."""

    error = "invalid_presentation_definition"
    error_description = "The presentation definition is invalid"


class PresentationDefinitionNotFoundError(OpenIdVerificationError):
    """The request is asking for a resource which doesn't exists"""

    error = "presentation_definition_not_found"
    error_description = "The presentation definition with the spcecified identifier wasn't found"

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(status.HTTP_404_NOT_FOUND, additional_error_description)


class AuthorizationRequestObjectNotFoundError(OpenIdVerificationError):
    """The request is asking for a resource which doesn't exists"""

    error = "authorization_request_object_not_found"
    error_description = "The authorization request object with the spcecified identifier wasn't found"

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(status.HTTP_404_NOT_FOUND, additional_error_description)


class AuthorizationRequestMissingError(OpenIdVerificationError):
    """The requestmissing an error_descrption"""

    error = "authorization_request_missing_error_param"
    error_description = "No complete Presentation found in the form data. In case of an error on the wallet side, at least the error parameter has to be submitted."


class VerificationProccessNotFoundError(OpenIdVerificationError):
    """The verification proccess with the spcecified identifier wasn't found"""

    error = "verification_proccess_not_found"
    error_description = "The verification proccess with the spcecified identifier wasn't found"

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(status.HTTP_404_NOT_FOUND, additional_error_description)


class VerificationProcessClosed(OpenIdVerificationError):
    error = "verification_process_closed"
    error_description = "The verification process is already completed. Additional responses are not allowed."

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(status.HTTP_400_BAD_REQUEST, additional_error_description)
