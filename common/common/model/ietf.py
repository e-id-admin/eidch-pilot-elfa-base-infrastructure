# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Collection of Pydantic models for IETF Objects
"""
import json
from jwcrypto import jwk
from functools import cached_property
from pydantic import BaseModel, ConfigDict, Field
from typing import Literal, Union, Optional

from common import parsing as prs


class JSONWebKey(BaseModel):
    """
    represents a cryptographic key
    https://datatracker.ietf.org/doc/html/rfc7517
    """

    model_config = ConfigDict(extra='allow')

    kty: str
    """
    key type
    https://datatracker.ietf.org/doc/html/rfc7517#section-4.1
    """

    use: str | None = None
    """
    Intended Use of the public key
    https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
    """

    key_ops: list[str] | None = None
    """
    https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
    """

    alg: str | None = None
    """
    Alogirhtm inteded for use with the key
    https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    """

    kid: str | None = None
    """
    Key ID, used to match sepcific keys
    https://datatracker.ietf.org/doc/html/rfc7517#section-4.5
    """

    # Missing multiple x5...

    def __eq__(self, other: object) -> bool:
        if isinstance(other, JSONWebKey):
            return self.as_pem() == other.as_pem()
        return False

    @cached_property
    def base64(self) -> str:
        """
        Returns the base64 encoded version of the key
        """
        json_string = json.dumps(self.model_dump(exclude={'base64'}, exclude_none=True), sort_keys=True)
        return prs.object_to_url_safe(json_string)

    @staticmethod
    def from_base64(base64_str: str):
        jwk_obj = prs.object_from_url_safe(base64_str)
        return JSONWebKey(**jwk_obj)

    def as_crypto_jwk(self) -> jwk.JWK:
        """Returns the crypto library object"""
        return jwk.JWK(**self.model_dump(exclude_none=True))

    def as_pem(self) -> bytes:
        """Returns the public key pem"""
        return self.as_crypto_jwk().export_to_pem()


class JSONWebKeyEllipticCurve(JSONWebKey):
    """
    https://www.rfc-editor.org/rfc/rfc7518#section-6.2
    """

    kty: Literal['EC']

    crv: str
    """
    Curve to use with x & y coordinates
    """

    x: str
    y: str


# TODO -> EID-1178: Test with other Keys than Elliptic Curve
class JSONWebKeySet(BaseModel):
    keys: list[Union[JSONWebKeyEllipticCurve, JSONWebKey]] = Field(discriminator="kty")

    def as_crypto_jwks(self) -> jwk.JWKSet:
        return jwk.JWKSet.from_json(self.model_dump_json(exclude_none=True))


class OAuth2Token(BaseModel):
    """
    https://www.rfc-editor.org/rfc/rfc6749.txt
    * access_token: The access token issued by the authorization server.
    * token_type: The type of the token issued
    * expires_in: The lifetime in seconds of the access token
    * refresh_token (Optional): The refresh token, which can be used to obtain new
         access tokens using the same authorization grant
    * scope (Optional): The scope of the access token
    """

    access_token: str
    """The access token issued by the authorization server."""
    token_type: str
    """The type of the token issued (eg. BEARER)"""
    expires_in: int
    """The lifetime in seconds of the access token"""
    refresh_token: Optional[str] = None
    """The refresh token, which can be used to obtain new
        access tokens using the same authorization grant"""
    scope: Optional[str] = None
    """The scope of the access token"""


class OpenID4VCToken(OAuth2Token):
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


class JsonWebTokenConfirmation(BaseModel):
    """
    THE cnf of JWT
    """

    jwk: Optional[JSONWebKey] = None
    jku: Optional[str] = None  # Not Implemented
