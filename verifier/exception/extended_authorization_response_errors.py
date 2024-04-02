# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
These Authorization Response Errors are beyond the standard, providing additional information to the user
"""

from .authorization_response_errors import InvalidRequestError


class CodedInvalidRequestError(InvalidRequestError):
    _optional_fields: list[str] = ["additional_error_description", "error_code"]
    error_code: str


class ExpiredJWTError(CodedInvalidRequestError):
    error_description = "Provided credential JWT is expired."
    error_code = "jwt_expired"


class ExpiredCredentialError(CodedInvalidRequestError):
    error_description = "Provided verifiable presentation is expired."
    error_code = "credential_expired"


class InvalidJWTFormatError(CodedInvalidRequestError):
    error_description = "JWT VC Data object with the data being located at $.vp is expected."
    error_code = "invalid_format"


class MissingNonceError(CodedInvalidRequestError):
    error_description = "Nonce is missing from Verifiable Presentation."
    error_code = "missing_nonce"


class InvalidNonceError(CodedInvalidRequestError):
    error_description = "Nonce is invalid"
    error_code = "invalid_nonce"


class UnsupportedCredentialFormat(CodedInvalidRequestError):
    error_description = "Server does not support the provided credential format"
    error_code = "unsupported_format"


class StatusListResolutionError(CodedInvalidRequestError):
    error_description = "Cannot resolve status list provided in credential"
    error_code = "unresolvable_status_list"


class CredentialRevokedError(CodedInvalidRequestError):
    error_description = "Provided credential is revoked."
    error_code = "credential_revoked"


class CredentialSuspendedError(CodedInvalidRequestError):
    error_description = "Provided credential is suspended."
    error_code = "credential_suspended"


class CredentialInvalidError(CodedInvalidRequestError):
    error_description = "Provided credential is not valid."
    error_code = "credential_invalid"


class HolderSignerMismatchError(CodedInvalidRequestError):
    error_description = "VP issuer and VC subject are not the same."
    error_code = "holder_binding_mismatch"


class MissingDataError(CodedInvalidRequestError):
    error_description = "Presented lacks requested attribute"
    error_code = "credential_missing_data"

    def __init__(self, status_code: int = 400, authorization_request_id: str = None, additional_error_description: str = None, attribute: str = None) -> None:
        super().__init__(status_code, authorization_request_id, additional_error_description)
        if attribute:
            self.error_description = f"{self.error_description} {attribute}"


class UnavailableKeyError(CodedInvalidRequestError):
    """Error for when fetching a key for verification fails"""

    error_description = "Failed to fetch public key for verification"
    error_code = "key_unavailable"


def exception_to_additional_error_description(msg: str, e: Exception):
    """Create the additional error description form the exception message & notes.
    * msg: some additional information helping to find out what went wrong
    * e: the exception causing the error
    """
    additional_information = f"{msg} - {repr(e)}"
    if hasattr(e, '__notes__'):
        additional_information += f" - {','.join(e.__notes__)}"
    return additional_information
