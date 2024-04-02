# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Based on OID4VC as of 2023-09-21
"""

##############
# OpenID4VCI #
##############
import json
from typing import Optional

from jwcrypto import jwt

from fastapi import HTTPException, status
from pydantic import BaseModel
from common import jwt_utils

import common.model.ietf as ietf
import common.model.openid4vc as cr
import common.parsing as prs


class CredentialDefinition(BaseModel):
    types: list[str]


class CredentialProof(BaseModel):
    proof_type: str
    jwt: str


class CredentialRequest(BaseModel):
    """
    https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#section-7.2
    * fromat: Requested format; has to be one of the offered formats
    * credential_definition:
    * proof: proof of possession of the key material
    """

    format: str
    """
    Requested format; has to be one of the offered formats. is one of ldp_vc or jwt_vc for now.
    """
    credential_definition: CredentialDefinition
    """
    Type gotten from .well-known/openid-configuration credentials_supported
    """
    proof: Optional[CredentialProof] = None
    """
    Proof of possession. the key material the issued Credential shall be bound to.
    Must contain proof_type
    # TODO -> EID-1248: Documentation is not working
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-key-proof-types
    """

    credential_encryption_jwk: Optional[ietf.JSONWebKey] = None
    """
    JWK used for encrypting the Credential Response
    """
    credential_response_encryption_alg: str = None
    """
    Algorithm of the credential_encryption_jwk
    If credential_response_encryption_alg is present, credential_encryption_jwk MUST be present
    see https://www.rfc-editor.org/info/rfc7516
    """
    credential_response_encryption_enc: str = None
    """
    Encryption for the JWK see 
    https://www.rfc-editor.org/info/rfc7516
    """


def process_credential_request_proof(proof: cr.CredentialProof) -> str:
    """
    Processes the credential request proof and returns the holder key
    Will throw HTTP exceptions if the proof is not correct
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-7.2.1
    """
    if proof.proof_type.lower() != "jwt":
        raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only supporting jwt proofs")
    jwt_parts = jwt_utils.split_jwt(proof.jwt)
    jwt_header = prs.object_from_url_safe(jwt_parts[0])
    # In theory required by the spec, but not possible with autlib.jose
    # if jwt_header.get("typ", "") != "openid4vci-proof+jwt":
    #     raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="typ in jwt header must be \"openid4vci-proof+jwt\"")
    if 'kid' in jwt_header:
        did: str = jwt_header['kid']
        if not did.lower().startswith("did:jwk"):
            raise HTTPException(status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, detail="Only supporting jwk did")
        jwk = prs.object_from_url_safe(did.split(":")[2])
    elif 'jwk' in jwt_header:
        jwk = jwt_header['jwk']
    else:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Must contain kid or jwk in header")
    try:
        jwk = ietf.JSONWebKey.model_validate(jwk)
        token = jwt.JWT(jwt=proof.jwt, key=jwk.as_crypto_jwk())  # Create token and validate it
        claims = json.loads(token.claims)
    except Exception as e:  # jwcrypto Validate can throw a great range of errors...
        desc = repr(e)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"JWT Decoding failed - {desc}")
    if 'nonce' not in claims:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Nonce must be contained in proof as \"nonce\": \"my-c_nonce-from-token\"")
    return did if did else jwk, claims['nonce']


class OpenID4VCToken(ietf.OAuth2Token):
    """
    Extended OAuth2.0 Token (https://www.rfc-editor.org/rfc/rfc6749.txt)
    * access_token: The access token issued by the authorization server.
    * token_type: The type of the token issued
    * expires_in: The lifetime in seconds of the access token
    * refresh_token (Optional): The refresh token, which can be used to obtain new access tokens using the same authorization grant
    * scope (Optional): The scope of the access token
    * c_nonce (Optional): nonce to be used to create a proof of possession of key material when requesting a Credential
    * c_nonce_expires_in (Optional): integer denoting the lifetime in seconds of the c_nonce
    """

    c_nonce: Optional[str] = None
    """
    nonce to be used to create a proof of possession of key material when requesting a Credential
    """
    c_nonce_expires_in: Optional[int] = None
    """
    integer denoting the lifetime in seconds of the c_nonce
    """
