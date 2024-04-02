# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import urllib.parse
import json
import datetime
import logging

import httpx
from fastapi import HTTPException, status

import common.key_configuration as key
import common.model.openid4vc as cr

from wallet import config as conf

_logger = logging.getLogger(__name__)


def get_issuer_openid_configuration(issuer_url: str, config: conf.WalletConfig):
    response = httpx.get(
        f"{issuer_url}/.well-known/openid-configuration",
        verify=config.enable_ssl_verification,
    )
    return response.json()


def fetch_openid4vci_credential(
    deeplink: str,
    key_conf: key.KeyConfiguration,
    config: conf.WalletConfig,
) -> dict:
    """
    Decodes the deeplink to fetch and return the credential
    according to openid4vc standard
    """
    offer = urllib.parse.urlparse(deeplink.strip("\""))
    # Offer has to be scheme openid-credential-offer
    # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-4.1.2
    assert offer.scheme == "openid-credential-offer"

    offer_payload = json.loads(dict(urllib.parse.parse_qsl(offer.query))['credential_offer'])
    pre_auth_info = offer_payload['grants']['urn:ietf:params:oauth:grant-type:pre-authorized_code']
    pre_auth_code = pre_auth_info['pre-authorized_code']

    oid_configuration = get_issuer_openid_configuration(offer_payload['credential_issuer'], config)

    # TODO -> EID-1185: Check if the offered credential is actually offered
    oid_issuer_config = httpx.get(
        f"{offer_payload['credential_issuer']}/.well-known/openid-credential-issuer",
        verify=config.enable_ssl_verification,
    )
    oid_issuer_config = oid_issuer_config.json()
    # TODO -> EID-1230: get issuer jwks

    # TODO -> EID-1186: add pin if pre_auth_info["user_pin_required"] == True
    token_response = httpx.post(
        oid_configuration['token_endpoint'],
        params={
            "grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code": pre_auth_code,
        },
        verify=config.enable_ssl_verification,
    )
    if token_response.status_code != 200:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to get the token {token_response.text}")
    oauth2_token = token_response.json()
    _logger.debug(f"OAuth2 token: {oauth2_token}")

    # Build the proof jwt
    # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.2.1
    proof_jwt_header = {"kid": key_conf.jwk_did, "alg": key_conf.signing_algorithm, "typ": "openid4vci-proof+jwt"}
    proof_jwt_claims = {
        # iss is optional
        "aud": oid_configuration['issuer'],  # Required
        "iat": round(datetime.datetime.now().timestamp()),  # Required
        "nonce": oauth2_token['c_nonce'],  # Optional, but required for proof verification
    }
    jwt = key_conf.encode_jwt(proof_jwt_claims, proof_jwt_header)

    credential_request = cr.CredentialRequest(
        format="jwt_vc_json", proof={"proof_type": "jwt", "jwt": jwt}, credential_definition=cr.CredentialDefinition(types=offer_payload['credentials'])
    )
    # Fetch the credential
    try:
        credential_response = httpx.post(
            oid_issuer_config['credential_endpoint'],
            headers={"authorization": f"BEARER {oauth2_token['access_token']}"},
            json=credential_request.model_dump(exclude_none=True),
            verify=config.enable_ssl_verification,
        )
    except httpx.ConnectError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Could not reach {oid_issuer_config['credential_endpoint']}, but I did reach {oid_configuration['token_endpoint']}",
        )
    return credential_response.json()
