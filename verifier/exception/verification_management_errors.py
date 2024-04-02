# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
To process the verification process a verification is created according to the naming / concept¨
introduced in the OpenId4VP specification
https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10.5
"""

from .authorization_response_errors import OpenIdVerificationError


class VerificationNotFinishedError(OpenIdVerificationError):
    """The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."""

    error = "verification_not_finished"
    error_description = "The verification has not reached a final state (error, success)"

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(404, additional_error_description)


class VerificationNotFoundError(OpenIdVerificationError):
    """The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed."""

    error = "verification_not_found"
    error_description = "The verification with the spcecified identifier wasn't found"

    def __init__(self, additional_error_description: str = None) -> None:
        super().__init__(404, additional_error_description)


class VerificationExpiredError(OpenIdVerificationError):
    """The verification has been successfully processed but the resposne data have already been expired"""

    error = "verification_expired"
    error_description = "The verification has been expired, therefore the response data can't be accessed anymore"
