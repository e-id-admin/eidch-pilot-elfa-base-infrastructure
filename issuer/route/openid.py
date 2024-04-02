# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Endpoints relating to the OpenID4VC, OpenId & OAuth 2.0 endpoints
"""

import time
import datetime

# Crypto
import logging

import fastapi
from fastapi import status

import common.key_configuration as key
import common.model.openid as oid
import common.db.postgres as db
import common.verifiable_credential as vc
import common.model.openid4vc as cr
import common.model.ietf as ietf


import issuer.config as conf
import issuer.builder as builder

import issuer.db.metadata as db_metadata
import issuer.db.credential as db_credential

import issuer.exception.credential_error_responses as ex

from issuer.logging import IssuerOperationsLogEntry

TAG = "OpenID"

_logger = logging.getLogger(__name__)

router = fastapi.APIRouter(tags=[TAG])

#############
# OAuth 2.0 #
#############


@router.post(
    "/token",
    responses={
        status.HTTP_400_BAD_REQUEST: {"model": ex.OpenIdError},
        status.HTTP_401_UNAUTHORIZED: {"model": ex.OpenIdError},
        status.HTTP_403_FORBIDDEN: {"model": ex.OpenIdError},
    },
)
def issue_access_token(
    request: fastapi.Request,
    session: db.inject,
) -> cr.OpenID4VCToken:
    """
    https://www.rfc-editor.org/rfc/rfc6749.txt
    Must be TLS!
    https://datatracker.ietf.org/doc/html/rfc6749?#section-4.1.4

    For the pre-authorized flow we get here the pre-authorized code & (maybe) a pin

    Data is transmitted as query parameters!
    """
    params = request.query_params

    # TODO -> EID-1182: Make the error responses according to OpenID4VCI standard.
    # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-token-error-response
    # Current errors are to hopefully help developers understand what is wrong, but not standard conform
    bearer_token_response = process_pre_authenticated_token_request(session, params)
    return bearer_token_response


def process_pre_authenticated_token_request(session, params):
    if "grant_type" not in params:
        # Failed to Authorize!
        raise ex.InvalidRequestException(additional_error_description="Missing grant type")

    grant_type = params.get("grant_type")
    if grant_type != "urn:ietf:params:oauth:grant-type:pre-authorized_code":
        raise ex.InvalidRequestException(additional_error_description="Incorrect grant type")

    offer: db_credential.CredentialOffer = db_credential.get_offer(session=session, offer_id=params.get("pre-authorized_code"))
    if not offer or offer.pin is not params.get("pin", None):
        raise ex.InvalidGrantException(additional_error_description="Incorrect pre-authorization_code & pin pair")
    if not offer.validity_check():
        session.commit()  # Save changes form validity check
        raise ex.InvalidGrantException(additional_error_description="Offer did expire")
    if offer.management.credential_status != db_credential.CredentialStatus.OFFERED.value:
        raise ex.InvalidGrantException(additional_error_description="Offer has already been used")
    offer.management.credential_status = db_credential.CredentialStatus.IN_PROGRESS.value

    expiration_time = 3600
    offer.offer_expiration_timestamp = round(time.time()) + expiration_time

    # TODO -> EID-1246: Consider how to make this nicer and not have a commit here...
    session.commit()
    token = cr.OpenID4VCToken.model_validate(
        {
            "access_token": str(offer.access_token),
            "token_type": "bearer",
            "expires_in": expiration_time,
            "c_nonce": str(offer.nonce),
            "c_nonce_expires_in": expiration_time,
        }
    )
    return token


##########
# OpenID #
##########


# We exclude_none to not have added in all optional parameters (like x5u for X.509 URL when we're using EC)
@router.get("/.well-known/jwks.json", response_model_exclude_none=True)
def get_jwk(key_conf: key.inject) -> ietf.JSONWebKeySet:
    """
    Return our authentication JWK
    This is not to be used for the VC!
    """
    return key_conf.jwks


@router.get("/.well-known/openid-configuration")
def get_openid_configuration(config: conf.inject) -> oid.OpenIdConfiguration:
    """
    When having our URI as the issuer field in a jwt, this endpoint is called.
    This is not to be used for the VC!
    The VC should reference to the base registry
    """
    uri = config.external_url
    registry_uri = f"{config.get_key_registry_uri()}"
    return {
        'issuer': uri,
        'jwks_uri': f'{registry_uri}/.well-known/jwks.json',
        'authorization_endpoint': f'{uri}/authorize',
        'token_endpoint': f'{uri}/token',
        # 'response_types_supported': ["code", "code id_token", "id_token", "token id_token"],
        'response_types_supported': ["id_token"],
        # 'subject_types_supported': ["public", "pairwise"],
        'id_token_signing_alg_values_supported': ['ES512'],
        # https://www.ietf.org/archive/id/draft-ietf-oauth-par-03.html#as_metadata
        "pushed_authorization_request_endpoint": f'{uri}/par',
        "request_uri_parameter_supported": True,
    }
    # TODO -> EID-1177: Complete with required


##############
# OpenID4VCI #
##############


@router.get("/.well-known/openid-credential-issuer", response_model_exclude_none=True)
def get_issuer_metadata(session: db.inject) -> vc.OpenIDCredentialIssuerData:
    """
    Issuer Metadata; What credentials can be received & where
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-10.2

    A Credential Issuer is identified by a case sensitive URL using
    the https scheme that contains scheme, host and, optionally,
    port number and path components, but no query or fragment components.

    A JSON array containing a list of JSON objects, each of them
    representing metadata about a separate credential type that the
    Credential Issuer can issue. The JSON objects in the array MUST conform
    to the structure of
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#credential-metadata-object
    """
    # TODO -> EID-1246: Prune Comment

    data = db_metadata.get_metadata(session)
    validated_data = vc.OpenIDCredentialIssuerData.model_validate(data)
    return validated_data


@router.post("/credential", responses={status.HTTP_400_BAD_REQUEST: {"model": ex.OpenIdError | ex.OpenIdErrorNonce}})
async def credential_issue(
    credential_request: cr.CredentialRequest, request: fastapi.Request, config: conf.inject, session: db.inject, key_conf: key.inject
) -> vc.OpenID4VerifiableCredentialJWT:
    """
    Issuing Credential using the authorization to figure out which credential should be issued
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-response

    Proof must be shaped as https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.2.1
    """
    try:
        if credential_request.format != "jwt_vc_json":
            raise ex.UnsupportedCredentialTypeException(additional_error_description="Only supporting jwt_vc_json")
        access_token = extract_bearer_token(request)

        holder_binding, nonce = cr.process_credential_request_proof(credential_request.proof)

        # TODO -> EID-1247: Support other methods
        if not holder_binding.startswith("did"):
            # TODO -> EID-1247: is this the correct exception type to raise?
            raise ex.UnsupportedCredentialFormatException(additional_error_description="Only supports did proof holder binding")
        # Check Basic request sanity
        if len(credential_request.credential_definition.types) < 1:
            raise ex.InvalidTokenException(additional_error_description="No Credential requested")
        if len(credential_request.credential_definition.types) > 1:
            raise ex.InvalidTokenException(additional_error_description="Bulk Credential Retrieval not supported")
        # Compare with offer
        offer = db_credential.get_offer_by_access_token_nonce(session, access_token, nonce)
        if not offer:
            raise ex.InvalidTokenException(additional_error_description="Incorrect access token & nonce combination")
        metadata = get_issuer_metadata(session=session)
        if offer.management.credential_status != db_credential.CredentialStatus.IN_PROGRESS.value:
            raise ex.InvalidTokenException(additional_error_description="Offer has already been used")
        # Compare with Credential Metadata
        requested_credential = credential_request.credential_definition.types[0]
        if requested_credential not in metadata.credentials_supported:
            raise ex.InvalidTokenException(additional_error_description="Requested Credential not found in offered credential")
        requested_credential_metadata = metadata.credentials_supported[requested_credential]
    except ex.OpenIdIssuanceException:
        _logger.exception("Error during credential issuance.")
        _logger.info(
            IssuerOperationsLogEntry(
                message="Error during credential issuance.",
                status=IssuerOperationsLogEntry.Status.error,
                operation=IssuerOperationsLogEntry.Operation.issuance,
                step=IssuerOperationsLogEntry.Step.issuance_delivery,
                # do not include management_id to prevent user tracking
            ),
        )
        raise
    credential_data = offer.offer_data
    # Convert to SD-JWT, if needed
    if requested_credential.startswith("sd_"):
        credential_data = builder.convert_to_sd_jwt(credential_data)

    vc_builder = builder.VerifiableCredentialBuilder(
        config=config,
        credential_type=requested_credential_metadata.credential_definition.type,
        holder_id=holder_binding,
        jwt_id=str(offer.management_id),
        credential_subject_data=credential_data,
        valid_from=offer.credential_valid_from,
        valid_until=offer.credential_valid_until,
    )
    if offer.credential_valid_until:
        # Use valid until time for JWT expiration
        until = datetime.datetime.fromisoformat(offer.credential_valid_until)
        jwt_expires = round(until.timestamp())
    else:
        jwt_expires = None  # Forever valid

    credential = vc_builder.create_oid_jwt(
        session=session,
        key_conf=key_conf,
        valid_until_timestamp=jwt_expires,
    )
    # TODO -> EID-1247: Move this somewhere more sensible
    offer.management.credential_status = db_credential.CredentialStatus.ISSUED.value
    if vc_builder.status_map:
        for association in offer.management.status_list_associations:
            association.status_list_index = vc_builder.status_map[association.status_list_id]['statusListIndex']

    _logger.info(
        IssuerOperationsLogEntry(
            message="Successfully delivered credential.",
            status=IssuerOperationsLogEntry.Status.success,
            operation=IssuerOperationsLogEntry.Operation.issuance,
            step=IssuerOperationsLogEntry.Step.issuance_delivery,
            seconds_until_expiry=offer.management.credential_offer.offer_expiration_timestamp - time.time(),
            # do not include management_id to prevent user tracking
        ),
    )

    # Delete offer data
    offer.remove_offer_data()
    session.commit()
    return credential


def extract_bearer_token(request: fastapi.Request) -> str:
    """
    Extracts the Bearer token UUID from the request headers
    """
    try:
        auth_header = request.headers.get('authorization')
        header_tokens: list[str] = auth_header.strip(' ').split(' ')
        assert len(header_tokens) == 2, "We Expect 'bearer <uuid>'"
        assert header_tokens[0].lower() == 'bearer'
        access_token = header_tokens[1].strip(' ')
    except Exception:
        raise ex.InvalidTokenException(additional_error_description=f"Expecting BEARER <token> but got `{auth_header}`.")
    return access_token
