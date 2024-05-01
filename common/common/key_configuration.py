# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Collection for loading and returning cryptographic keys in the required formats.


"""

import os
import ssl
from typing import Annotated
from functools import cache

from fastapi import Depends
from jwcrypto import jwk, jws, common as jw_common
from sd_jwt.issuer import SDJWTIssuer
import pkcs11
import pkcs11.util.ec

import common.hsm.override as hsm_override
from common.parsing import object_to_url_safe
import common.model.ietf as ietf


def _load_key_file(key_file: str) -> str:
    with open(key_file) as f:
        return f.read()


def _load_key(env_var: str, file: str) -> str:
    key = os.getenv(env_var)
    if not key:
        key = _load_key_file(file)
    return key


class KeyConfiguration:
    """
    Holds Public & Private Keys
    """

    @staticmethod
    def load(key_folder: str = "cert"):
        public_key = _load_key(env_var="SIGNING_KEY_PUBLIC", file=f"{key_folder}/ec_public.pem")
        private_key = _load_key(env_var="SIGNING_KEY_PRIVATE", file=f"{key_folder}/ec_private.pem")
        signing_algorithm = os.getenv("SIGNING_ALGORITHM", "ES512")
        return KeyConfiguration(public_key, private_key, signing_algorithm)

    def __init__(self, public_key: str, private_key: str, signing_algorithm: str):
        """
        Keys are the pem bytes utf-8 encoded
        """
        self._public_key: str = public_key
        self._private_key: str = private_key
        self.signing_algorithm: str = signing_algorithm
        self.public_jwk = jwk.JWK.from_pem(public_key.encode())
        self.private_jwk = jwk.JWK.from_pem(private_key.encode())

    def get_pk(self):
        return self._public_key

    def encode_jwt(self, payload: dict, header: dict = None) -> str:
        """
        typ: vc+sd-jwt for sd-jwts
        https://datatracker.ietf.org/doc/html/draft-terbu-sd-jwt-vc-02#name-header-parameters-4
        """
        if not header:
            header = {}
        if 'alg' not in header:
            header['alg'] = self.signing_algorithm
            header['typ'] = 'vc+jwt'

        encoded_claims = jw_common.json_encode(payload)
        encoded_header = jw_common.json_encode(header)
        signer = jws.JWS(encoded_claims)
        signer.add_signature(key=self.private_jwk, protected=encoded_header)
        return signer.serialize(compact=True)

    def encode_sd_jwt(self, payload: dict, header=None) -> str:
        sd_issuer = SDJWTIssuer(
            payload,
            self.private_jwk,
            sign_alg=self.signing_algorithm,
            extra_header_parameters={"typ": "vc+sd-jwt"},
        )
        return sd_issuer.sd_jwt_issuance

    @property
    def jwks(self) -> dict:
        """
        JSON Web Key Set with public signing key
        """
        return {"keys": [self.public_jwk.export_public(as_dict=True)]}

    @property
    def jwk_did(self) -> str:
        """
        DID JWK with public signing key
        """
        return f'did:jwk:{object_to_url_safe(self.public_jwk.export_public(as_dict=True))}'

    def public_key_as_dto(self) -> ietf.JSONWebKey:
        """Returns the public key as pydantic data transfer object"""
        return ietf.JSONWebKey.model_validate(self.public_jwk.export_public(as_dict=True))


class HardwareSecurityModuleKeyConfiguration(KeyConfiguration):
    """
    Key Configuration for use with HSM
    Overrides some Crypto Library functionalities to use
    HSM private key link to sign JWTs & SD-JWTS.

    Opens a session to the HSM at creation time.
    """

    def __init__(
        self,
        library_path: str,
        token_label: str,
        user_pin: str,
        key_label: str,
        signing_algorithm: str,
    ) -> "HardwareSecurityModuleKeyConfiguration":
        """
        * library_path: posix path
        * token_label: hsm token label
        * user_pin: pin for the token on the hsm
        * key_label: label under which the key is saved

        Loads public key from HSM & keeps an open session to the HSM.
        """
        self._session: pkcs11.Session = None
        if not os.path.exists(library_path):
            raise LookupError(f"Can not find hsm shared object library {library_path}")
        try:
            lib = pkcs11.lib(library_path)
        except pkcs11.AlreadyInitialized:
            lib = pkcs11._lib
        token: pkcs11.Token = lib.get_token(token_label=token_label)
        self._session = token.open(user_pin=user_pin)
        self._key_label = key_label
        self.public_jwk = self._load_public_jwk()
        self.private_key = self._prepare_private_key_link()
        self.signing_algorithm = signing_algorithm

    def __del__(self):
        if self._session:
            self._session.close()

    def get_pk(self) -> pkcs11.constants.ObjectClass.PUBLIC_KEY:
        return self._session.get_key(
            label=self._key_label,
            object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY,
        )

    def _load_public_jwk(self) -> tuple[str, jwk.JWK]:
        """Loads the public key from the HSM, returing public key jwk"""
        hsm_pk = self.get_pk()
        openssl_pk_der = pkcs11.util.ec.encode_ec_public_key(hsm_pk)
        # we now have the bytes of the public key (DER format)
        openssl_cert = ssl.DER_cert_to_PEM_cert(openssl_pk_der)
        # Format is now PEM
        # Conversion does not know / forget that this is a public key
        # We replace BEGIN/END CERTIFICATE with BEGIN/END PUBLIC KEY
        openssl_pk_pem = openssl_cert.replace(
            "CERTIFICATE-----",
            "PUBLIC KEY-----",
        )
        pk_jwk = jwk.JWK.from_pem(openssl_pk_pem.encode())
        return pk_jwk

    def _prepare_private_key_link(self) -> pkcs11.PrivateKey:
        """
        Prepares the private key link object which can be
        used as long as the session remains open
        """
        return self._session.get_key(
            label=self._key_label,
            object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY,
        )

    def public_key_as_dto(self) -> ietf.JSONWebKey:
        """Returns the public key as pydantic data transfer object"""
        return ietf.JSONWebKey.model_validate(self.public_jwk.export_public(as_dict=True))

    def encode_jwt(self, payload: dict, header=None) -> str:
        """
        typ: vc+sd-jwt for sd-jwts
        https://datatracker.ietf.org/doc/html/draft-terbu-sd-jwt-vc-02#name-header-parameters-4
        """
        if not header:
            header = {}
        if 'alg' not in header:
            header['alg'] = self.signing_algorithm
            header['typ'] = 'vc+jwt'

        encoded_claims = jw_common.json_encode(payload)
        encoded_header = jw_common.json_encode(header)
        signer = hsm_override.JWS(encoded_claims)

        signer.add_signature(key=self.private_key, protected=encoded_header)
        jwt = signer.serialize(compact=True)
        return jwt

    def encode_sd_jwt(self, payload: dict, header=None) -> str:
        """
        Encodes the payload as selective disclosure jwt
        attributes which should be created as selective
        disclosure should be `sd_jwt.common.SDObj`.
        """
        sd_issuer = hsm_override.SDJWTIssuer(
            payload,
            self.private_key,
            sign_alg=self.signing_algorithm,
            extra_header_parameters={"typ": "vc+sd-jwt"},
        )
        return sd_issuer.sd_jwt_issuance


@cache
def get_key_configuration() -> KeyConfiguration:
    if "HSM_LIBRARY" in os.environ:
        return HardwareSecurityModuleKeyConfiguration(
            library_path=os.environ['HSM_LIBRARY'],
            token_label=os.environ['HSM_TOKEN'],
            user_pin=os.environ['HSM_PIN'],
            key_label=os.environ['HSM_LABEL'],
            signing_algorithm=os.environ['HSM_SIGNING_ALGORITHM'],
        )
    return KeyConfiguration.load()


inject = Annotated[KeyConfiguration, Depends(get_key_configuration)]
