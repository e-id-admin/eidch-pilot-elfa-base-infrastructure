# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import jsonpath_ng as jsonpath
import json
import os
import copy
import logging

# SD JWT Unpacker
from sd_jwt.common import SDJWTCommon
from sd_jwt.verifier import SDJWTVerifier
from jwcrypto.jws import JWS

from common import parsing as prs
import common.httpx_wrapper as httpxw
from common.model import ietf
from common import config as conf


REGISTRY_BASE_URL = os.getenv('REGISTRY_BASE_URL', 'https://registry_base/issuer')

_sdjwt_common = SDJWTCommon("json")
_logger = logging.getLogger(__name__)


class SDJWT_Unpacker(SDJWTVerifier):
    """
    This removes the verification functionality from the SDJWTVerifier.
    So one can use it to extract the sd_claims without verify the sdjwt.
    TODO: This is a hack.
    TODO: Check if this functionality is already supported. It was not in the version: 0.9.1
    """

    def __init__(
        self,
        sd_jwt_presentation: str,
        serialization_format: str = "compact",
    ):
        SDJWTCommon.__init__(self, serialization_format=serialization_format)

        self._parse_sd_jwt(sd_jwt_presentation)
        self._create_hash_mappings(self._input_disclosures)
        parsed_input_sd_jwt = JWS()
        parsed_input_sd_jwt.deserialize(self._unverified_input_sd_jwt)
        self._sd_jwt_payload = json.loads(parsed_input_sd_jwt.objects["payload"].decode("utf-8"))

    def extract_sd_claims(self):
        """
        Returns the body of the SDJWT where all the disclosed values are replaced with the actual values
        """
        return self._extract_sd_claims()


def hash(value: str) -> str:
    """
    Returns the hash of the value.
    """
    return _sdjwt_common._b64hash(value)


def split_jwt(jwt: str) -> list[str]:
    """
    Splits a JWT into its head at index 0, body at index 1, signature at index 2.
    """
    return jwt.split(".")


def is_sd_jwt(jwt: str) -> bool:
    """
    Checks if the JWT is a SD-JWT.
    """
    return "~" in jwt


def compose_sd_jwt(jwt: str, secrets: list[str]) -> str:
    """
    Composes a SD-JWT from a JWT and a list of secrets.
    """
    return f"{jwt}~{'~'.join(secrets)}~"


def get_jwt_of_sdjwt(sdjwt: str) -> str:
    """
    SD-JWT has the form <jwt>~<sd1>~<sd2>~...~<sdn>~
    This will return the <jwt> part.
    """
    return sdjwt.split("~")[0]


def get_secrets_of_sdjwt(sdjwt: str) -> list[str]:
    """
    SD-JWT has the form <jwt>~<sd1>~<sd2>~...~<sdn>~
    This will return [<sd1>, <sd2>, ..., <sdn>]
    Ommits empty secrets (eg ~~)
    """
    secrets = sdjwt.split("~")[1:-1]
    return list(filter(any, secrets))


def get_jwks(issuer_id: str, config: conf.Config) -> ietf.JSONWebKeySet:
    """
    Tries to get the JWK from the issuer id.
    """
    if is_did_identifier(issuer_id):
        if is_did_jwk_identifier(issuer_id):
            return ietf.JSONWebKeySet(keys=[get_jwk_from_did_jwk(issuer_id)])
        raise NotImplementedError("DID is not supported yet.")
    if is_url_identifier(issuer_id):
        return get_jwk_set_from_url(issuer_id, config)
    return get_jwk_set_from_id(issuer_id, config)


def _get_jwk(url: str, config: conf.Config) -> ietf.JSONWebKeySet:
    keys = httpxw.get(
        url,
        config,
    ).json()['keys']
    return ietf.JSONWebKeySet(keys=[ietf.JSONWebKey(**key) for key in keys])


def get_jwk_set_from_id(id: str, config: conf.Config) -> ietf.JSONWebKeySet:
    """
    This assumes the issuer is registered on the base registry.
    """
    url = f"{REGISTRY_BASE_URL}/{id}/.well-known/jwks.json"
    return _get_jwk(url, config)


def get_jwk_set_from_url(url: str, config: conf.Config) -> ietf.JSONWebKeySet:
    """
    Return the JWK keyset from the issuer. If the issuer is identified by an URI
    Expect the URI destination to provide the .well-known/openid-configuration
    """
    openid_config = httpxw.get(
        f'{url}/.well-known/openid-configuration',
        config,
    ).json()
    return _get_jwk(openid_config['jwks_uri'], config)


def get_jwk_from_did_jwk(did_jwk: str) -> ietf.JSONWebKey:
    """
    Returns the JWK from a DID JWK.
    """
    return ietf.JSONWebKey(**prs.object_from_url_safe(did_jwk.lstrip("did:jwk:")))


def is_url_identifier(identifier: str) -> bool:
    """
    Checks if the identifier is a URL identifier.
    """
    return identifier.startswith("https://") or identifier.startswith("http://")


def is_did_identifier(identifier: str) -> bool:
    """
    Checks if the identifier is a valid DID identifier.
    """
    return identifier.startswith("did:")


def is_did_jwk_identifier(identifier: str) -> bool:
    """
    Checks if the identifier is a valid DID identifier.
    """
    return identifier.startswith("did:jwk:")


def find_sd_matches(dictionary) -> list:
    return jsonpath.parse("$.._sd[*]").find(dictionary)


def deep_merge(dict_a, dict_b):
    merged = copy.deepcopy(dict_b)
    for k, v in dict_a.items():
        if k in merged:
            if isinstance(merged[k], dict) and isinstance(v, dict):
                merged[k] = deep_merge(merged[k], v)
            elif isinstance(merged[k], list) and isinstance(v, list):
                merged[k] += v
            else:
                merged[k] = v
        else:
            merged[k] = copy.deepcopy(v)
    return merged
