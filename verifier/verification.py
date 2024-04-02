# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
from datetime import datetime

# Crypto
from jwcrypto import jwt
from pydantic import ValidationError

# Handle json path queries
from common import jwt_utils
from common.model import ietf
import common.verifiable_credential as vc
import common.model.dif_presentation_exchange as dif
import common.status_list as sl
import common.httpx_wrapper as httpxw

import verifier.cache.verifier_cache as cache
import verifier.exception as err
import verifier.models as models
from verifier import config as conf
from verifier.logging import VerifierOperationsLogEntry

_logger = logging.getLogger(__name__)


def is_expired(jwt: vc.JsonWebToken) -> bool:
    """
    Checks if the JWT is expired.
    """
    if "exp" not in jwt.body:
        # If expiration date is not set, it is not expired by convention
        return False
    expiration_time = jwt.body["exp"]

    # Convert expiration time to datetime object (POSIX timestamp)
    expiration_datetime = datetime.fromtimestamp(expiration_time)
    now = datetime.now()
    # Check if expiration time has passed
    return expiration_datetime < now


def verify_valid_jwt(token: vc.JsonWebToken, jwks: ietf.JSONWebKeySet) -> None:
    """
    Checks if the JWT has a valid signature.

    May throw `jwt.JWException` exceptions if not valid.
    """
    jwt_token = jwt.JWT(jwt=token.to_raw())
    # Workaround:
    # having a key in a key set without key id will cause jwcrypto to ignore that key
    # android & ios library do not provide a key id...
    if len(jwks.keys) == 1:
        # This is used for holder key
        jwt_token.validate(jwks.keys[0].as_crypto_jwk())
    else:
        # This is generally used for the issuer key set
        jwt_token.validate(key=jwks.as_crypto_jwks())


def is_valid_jwt(token: vc.JsonWebToken, jwks: ietf.JSONWebKeySet) -> bool:
    """
    Checks if the JWT has a valid signature.
    """
    try:
        verify_valid_jwt(token, jwks)
    except jwt.JWException:
        return False
    return True


def is_valid_sd_jwt(sd_jwt: vc.SelectiveDisclosureJsonWebToken, key: ietf.JSONWebKey) -> bool:
    """
    Checks if the JWT has a valid signature and if all selective disbclosures match the hashes in the vc.
    """
    if not is_valid_jwt(sd_jwt.jwt, key):
        return False
    try:
        vc.SelectiveDisclosureJsonWebToken.model_validate(sd_jwt)
        return True
    except ValidationError:
        return False


def verify_presentation(request_object: models.VerificationRequestObject, presentation: vc.OpenID4VerifiablePresentationResponse, config=conf.VerifierConfig) -> None:
    """
    Verifies the VC presentation.
    https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#section-6.1
    """

    presentation_jwt = presentation.vp_token_jwt
    authorization_request_id = request_object.id
    try:
        try:
            wallet_jwks = jwt_utils.get_jwks(presentation_jwt.body.iss, config)
        except Exception as e:
            error_msg = "Failed to fetch Wallet JWKS"
            _logger.exception(error_msg)
            raise err.UnavailableKeyError(
                authorization_request_id=authorization_request_id,
                additional_error_description=err.exception_to_additional_error_description(error_msg, e),
            )

        # Check signature
        if not is_valid_jwt(presentation.vp_token_jwt, wallet_jwks):
            raise err.CredentialInvalidError(
                authorization_request_id=authorization_request_id,
                additional_error_description="Validation for Verifiable Presentation JWT failed.",
            )

        # Checks if the presentation is expired and if it can already be used
        if not presentation_jwt.body.is_date_valid():
            raise err.ExpiredJWTError(authorization_request_id=authorization_request_id)

        # Check if body of the JWT is a VC
        if not isinstance(presentation_jwt.body, vc.JsonWebTokenBodyVCData):
            raise err.InvalidJWTFormatError(authorization_request_id=authorization_request_id)

        if not presentation_jwt.body.vp:
            raise err.InvalidJWTFormatError(authorization_request_id=authorization_request_id)

        # Checks if the credential is expired and if it can already be used
        if not presentation_jwt.body.vp.is_date_valid():
            raise err.ExpiredCredentialError(authorization_request_id=authorization_request_id)

        # Check if nonce is provided
        if presentation_jwt.body.nonce is None:
            raise err.MissingNonceError(authorization_request_id=authorization_request_id)

        # Check if jwt nonce matches request nonce
        if presentation_jwt.body.nonce != request_object.nonce:
            raise err.InvalidNonceError(authorization_request_id=authorization_request_id)

        credentials = presentation_jwt.body.vp.verifiableCredential
        credentials: list[str | vc.VerifiableCredential] = [credentials] if not isinstance(credentials, list) else credentials

        for credential in credentials:
            if not isinstance(credential, str):
                raise err.UnsupportedCredentialFormat(authorization_request_id=authorization_request_id)
            try:
                if jwt_utils.is_sd_jwt(
                    credential
                ):  # TODO -> EID-1233 this should be done using typ field in the header and not by checking the content: it should be vp+jwt or vp+sd-jwt
                    credential = vc.SelectiveDisclosureJsonWebToken.from_str(credential)
                    verify_sd_jwt_in_presentation(credential, wallet_jwks, request_object, config)
                else:
                    credential = vc.JsonWebToken.from_str(credential)
                    verify_jwt_in_presentation(credential, wallet_jwks, request_object, config)
            except jwt.JWTExpired as e:
                raise err.ExpiredJWTError(
                    authorization_request_id=authorization_request_id,
                    additional_error_description=str(e),
                )
            except jwt.JWException as e:
                raise err.CredentialInvalidError(
                    authorization_request_id=authorization_request_id,
                    additional_error_description=f"Validation for credential in Verifiable Presentation JWT failed. Reason: {str(e)}",
                )

        authorization_response_data: models.AuthorizationResponseData = models.AuthorizationResponseData.from_OpenID4VerifiablePresentationResponse(
            config.verification_ttl, presentation
        )
        authorization_response_data.vp_token = vc.JsonWebTokenBodyVCData.model_validate(credential.body).vc.credentialSubject.model_dump(exclude={"_sd"})
        cache.authorization_response_data_service.set(authorization_response_data, authorization_request_id)
        cache.verification_management_service.set_verification_status(
            expiresAt=authorization_response_data.expires_at, authorization_request_id=authorization_request_id, status=models.VerificationStatus.SUCCESS
        )
        _logger.info(
            VerifierOperationsLogEntry(
                message="Verification successful.",
                status=VerifierOperationsLogEntry.Status.success,
                operation=VerifierOperationsLogEntry.Operation.verification,
                step=VerifierOperationsLogEntry.Step.verification_evaluation,
                # do not include management_id to prevent user tracking
            ),
        )
    except err.CodedInvalidRequestError as e:
        _logger.info(
            VerifierOperationsLogEntry(
                message="Verification request invalid.",
                status=VerifierOperationsLogEntry.Status.error,
                operation=VerifierOperationsLogEntry.Operation.verification,
                step=VerifierOperationsLogEntry.Step.verification_evaluation,
                error_code=e.error_code,
                # do not include management_id to prevent user tracking
            ),
        )
        # rethrow error to be send to client
        raise
    except Exception:
        _logger.exception("Verification aborted.")
        _logger.info(
            VerifierOperationsLogEntry(
                message="Verification aborted.",
                status=VerifierOperationsLogEntry.Status.error,
                operation=VerifierOperationsLogEntry.Operation.verification,
                step=VerifierOperationsLogEntry.Step.verification_evaluation,
                error_code='invalid_request',
                # do not include management_id to prevent user tracking
            ),
        )
        # rethrow error to be send to client
        raise


def _check_status(
    jwt_body: vc.JsonWebTokenBodyVCData,
    purpose: str,
    authorization_request_id: str,
    config: conf.VerifierConfig,
):
    """
    Checks status of the VC
    Returns true if any of the status has been set
    """

    def _check_status_list(status_entry):
        """
        Fetches the status list from the registry.
        Returns true if the index for the credential is set
        """
        credential_status_id = status_entry.id  # The url of the status list
        if status_entry.statusPurpose != purpose:
            return False

        # GET the status list
        status_list_index = int(status_entry.statusListIndex)
        try:
            status_request = httpxw.get(credential_status_id, config)
        except httpxw.ConnectError as e:
            error_msg = f"Can not get status for {purpose}"
            _logger.exception(error_msg)
            raise err.StatusListResolutionError(
                authorization_request_id=authorization_request_id,
                additional_error_description=err.exception_to_additional_error_description(error_msg, e),
            )
        if status_request.status_code != 200:
            raise err.StatusListResolutionError(
                authorization_request_id=authorization_request_id,
                additional_error_description=f"Failed to get Status List with {status_request.status_code} - {status_request.text}",
            )

        # Check if status list is valid
        status_list_vc = status_request.content[1:-1].decode("utf8")  # The status list as a jwt
        status_list_vc = vc.JsonWebToken.from_str(status_list_vc)
        try:
            jwk = jwt_utils.get_jwks(status_list_vc.body.iss, config)
        except Exception as e:
            error_msg = "Failed to fetch Status List Issuer JWKS"
            _logger.exception(error_msg)
            raise err.UnavailableKeyError(
                authorization_request_id=authorization_request_id,
                additional_error_description=err.exception_to_additional_error_description(error_msg, e),
            )
        if not is_valid_jwt(status_list_vc, jwk):
            raise err.StatusListResolutionError(authorization_request_id=authorization_request_id)
        jwt_body = status_list_vc.body
        if not isinstance(jwt_body, vc.JsonWebTokenBodyVCData):
            raise err.StatusListResolutionError(authorization_request_id=authorization_request_id)

        # Get status from Status VC
        revocation_list = jwt_body.vc.credentialSubject
        statuslist = sl.from_string(revocation_list.encodedList)
        encoded_list = statuslist.data
        return bool(encoded_list[status_list_index])

    # CHECK purpose
    status_entries = jwt_body.vc.credentialStatus
    if not isinstance(status_entries, list):
        status_entries = [status_entries]
    # See if any of the status list have their index set
    return any(map(_check_status_list, status_entries))


def is_suspended_vc(
    jwt_body: vc.JsonWebTokenBodyVCData,
    authorization_request_id: str,
    config: conf.VerifierConfig,
) -> bool:
    return _check_status(jwt_body, "suspension", authorization_request_id, config)


def is_revoked_vc(
    jwt_body: vc.JsonWebTokenBodyVCData,
    authorization_request_id: str,
    config: conf.VerifierConfig,
) -> bool:
    return _check_status(jwt_body, "revocation", authorization_request_id, config)


def verify_sd_jwt_in_presentation(
    sd_jwt: vc.SelectiveDisclosureJsonWebToken,
    jwks_issuer: ietf.JSONWebKeySet,
    request_object: models.VerificationRequestObject,
    config: conf.VerifierConfig,
) -> None:
    validated_body = vc.JsonWebTokenBodyVCData.model_validate(sd_jwt.body)
    validated_jwt = vc.JsonWebToken.model_validate(sd_jwt.jwt)
    # .jwt gives the unchanged credential
    # .body resolves all possible selective disclosures
    verify_jwt_cryptographic(validated_jwt, request_object.id, config)
    verify_jwt_semantics(validated_body, jwks_issuer, request_object, config)


def verify_jwt_semantics(
    jwt_body: vc.JsonWebTokenBodyVCData,
    jwks_issuer: ietf.JSONWebKeySet,
    request_object: models.VerificationRequestObject,
    config: conf.VerifierConfig,
) -> None:

    if config.filter_allowed_issuers_regex.match(jwt_body.iss) is None:
        msg = f"Issuer ({jwt_body.iss}) of verifiable credential is not allowed in this environment (allowed issuers: {config.filter_allowed_issuers_regex})."
        _logger.warning(msg)
        raise err.CredentialInvalidError(
            authorization_request_id=request_object.id,
            additional_error_description=msg,
        )

    if is_revoked_vc(jwt_body, request_object.id, config):
        raise err.CredentialRevokedError(authorization_request_id=request_object.id)
    if is_suspended_vc(jwt_body, request_object.id, config):
        raise err.CredentialSuspendedError(authorization_request_id=request_object.id)
    if not jwt_body.is_date_valid():
        raise err.ExpiredCredentialError(authorization_request_id=request_object.id)

    # Check vp
    if jwt_body.cnf is not None:
        # TODO: Could also be in sub or vc.credentialSubject.id
        if jwt_body.cnf.jwk not in jwks_issuer.keys:
            raise err.HolderSignerMismatchError(authorization_request_id=request_object.id)

    # Assumes we only have one input descriptor
    input_descriptor = request_object.presentation_definition.input_descriptors[0]
    try:
        validated_attributes = dif.get_validated_attributes(input_descriptor, jwt_body.model_dump())
    except dif.MissingAttributeException as e:
        raise err.MissingDataError(authorization_request_id=request_object.id, attribute=e.attribute)

    f"The following values were provided: {validated_attributes}"
    # TODO: Add business logic (e.g. check if the average grade is high enough)


def verify_jwt_cryptographic(
    jwt: vc.JsonWebToken,
    authorization_request_id: str,
    config: conf.VerifierConfig,
) -> None:
    # Check if the JWT is signed by the jwk on the base registry (Assumes only one key is in the keyset)
    body = vc.JsonWebTokenBodyVCData.model_validate(jwt.body)
    try:
        issuer_jwk = jwt_utils.get_jwks(body.iss, config)
    except Exception as e:
        error_msg = "Failed to fetch Issuer JWKS"
        _logger.exception(error_msg)
        raise err.UnavailableKeyError(
            authorization_request_id=authorization_request_id,
            additional_error_description=err.exception_to_additional_error_description(error_msg, e),
        )

    verify_valid_jwt(jwt, issuer_jwk)


def verify_jwt_in_presentation(
    jwt: vc.JsonWebToken,
    vp_issuer: ietf.JSONWebKey,
    request_object: models.VerificationRequestObject,
    config: conf.VerifierConfig,
) -> None:
    validated_body = vc.JsonWebTokenBodyVCData.model_validate(jwt.body)
    verify_jwt_cryptographic(jwt, request_object.id, config)
    verify_jwt_semantics(validated_body, vp_issuer, request_object, config)
