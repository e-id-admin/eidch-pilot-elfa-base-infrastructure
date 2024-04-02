# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Models for communicating in a secure fashion with the registry
"""
import json

from pydantic import BaseModel
from jwcrypto import jwt

from common.model import ietf


class UpdateJWT(BaseModel):
    """
    Update JWT for a Status VC.
    Must contain
    * sub - the same issuer_id as provided in the url
    * nonce - provided by the nonce endpoint
    * payload - the status list entry verifiable credential as jwt
    """

    update_jwt: str

    def extract_claims(self, jwks: ietf.JSONWebKeySet) -> dict:
        """
        Attempts to extact claims. Throws JWException if validation fails with all keys.

        """
        return json.loads(jwt.JWT(jwt=self.update_jwt, key=jwks.as_crypto_jwks()).claims)


class VerificationError(Exception):
    def __init__(self, detail: str, *args):
        super().__init__(args)
        self.detail = detail


def verify_nonce(nonce: str, claims: dict):
    if 'nonce' not in claims:
        raise VerificationError(detail="Nonce is missing")
    if nonce != claims['nonce']:
        raise VerificationError(detail="Invalid nonce")


def verify_subject(subject_id: str, claims: dict):
    if 'sub' not in claims:
        raise VerificationError(detail="Subject missing, expecting issuer_id")
    if claims['sub'] != subject_id:
        raise VerificationError(detail=f"Subject mismatch; {claims['sub']} != {subject_id}")
