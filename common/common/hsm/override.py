# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Overrides for jwcrypot library to make it work with HSM"""

import typing
from dataclasses import dataclass
import json
import jwcrypto.jws as jws
import sd_jwt.issuer as sd_jwt_i
import pkcs11

import cryptography.hazmat.primitives.hashes as hazmat_hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed


@dataclass
class MappingHelper:
    mechanism: pkcs11.Mechanism
    algorithm: hazmat_hashes.HashAlgorithm


MAPPING = {
    'ES256': MappingHelper(
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
        algorithm=hazmat_hashes.SHA256(),
    ),
    'ES512': MappingHelper(
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
        algorithm=hazmat_hashes.SHA512(),
    ),
}
"""Provides a link from JWT alg to the underlying pkcs11 mechanism & hasing algorithm"""


def _jws_core_transform_data(protected: str | dict, payload: str | dict) -> bytes:
    """
    emulates the jws core transformations which are done partially in jwscore init
    https://github.com/latchset/jwcrypto/blob/v1.5.0/jwcrypto/jws.py#L97-L128

    and sign
    https://github.com/latchset/jwcrypto/blob/v1.5.0/jwcrypto/jws.py#L146-L155

    """
    if isinstance(protected, dict):
        protected = jws.json_encode(protected)
    if isinstance(payload, dict):
        payload = jws.json_encode(payload)

    return b'.'.join(
        [
            jws.base64url_encode(protected).encode('utf-8'),
            jws.base64url_encode(payload).encode('utf-8'),
        ]
    )


def _calculate_digest_and_algorithm(
    data: bytes,
    algorithm: typing.Union[Prehashed, hazmat_hashes.HashAlgorithm],
) -> typing.Tuple[bytes, hazmat_hashes.HashAlgorithm]:
    """Copied utils function from cryptography library
    https://github.com/pyca/cryptography/blob/41.0.x/src/cryptography/hazmat/backends/openssl/utils.py#L46
    """
    if not isinstance(algorithm, Prehashed):
        hash_ctx = hazmat_hashes.Hash(algorithm)
        hash_ctx.update(data)
        data = hash_ctx.finalize()
    else:
        algorithm = algorithm._algorithm

    if len(data) != algorithm.digest_size:
        raise ValueError("The provided data must be the same length as the hash algorithm's digest size.")

    return (data, algorithm)


def _create_signing_data(protected: str | dict, payload: str | dict, algorithm: hazmat_hashes.HashAlgorithm) -> bytes:
    """
    Transforms the protected header & payload
    in the same way as jwcrypto and creates a
    SHA512 hash for it.
    """
    data = _jws_core_transform_data(protected, payload)
    hashed_data, algorithm = _calculate_digest_and_algorithm(data, algorithm)
    return hashed_data


class JWS(jws.JWS):
    """
    Overridden version of JWS for signing with a hsm,
    skips any checks for the private key.
    """

    def add_signature(
        self,
        key: pkcs11.PrivateKey,
        alg=None,
        protected: dict = None,
        header: dict = None,
    ):
        """
        Adds a new signature to the object.
        * key: pkcs11 private key
        * alg: jws algorithm; used to determine hsm method
        * protected: The protected header (optional)

        Copies most of
        https://github.com/latchset/jwcrypto/blob/v1.5.0/jwcrypto/jws.py#L477-L566
        Overrides the part where the jwt data is hashes and signed
        """
        b64 = True

        if protected:
            if isinstance(protected, dict):
                protected = jws.json_encode(protected)
            # Make sure p is always a deep copy of the dict
            p = jws.json_decode(protected)
        else:
            p = dict()

        # If b64 is present we must enforce criticality
        if 'b64' in list(p.keys()):
            crit = p.get('crit', [])
            if 'b64' not in crit:
                raise jws.InvalidJWSObject('b64 header must always be critical')
            b64 = p['b64']

        if 'b64' in self.objects:
            if b64 != self.objects['b64']:
                raise jws.InvalidJWSObject('Mixed b64 headers on signatures')

        h = None
        if header:
            if isinstance(header, dict):
                header = jws.json_encode(header)
            # Make sure h is always a deep copy of the dict
            h = jws.json_decode(header)

        p = self._merge_check_headers(p, h)

        if 'alg' in p:
            if alg is None:
                alg = p['alg']
            elif alg != p['alg']:
                raise ValueError('"alg" value mismatch, specified "alg" ' 'does not match JOSE header value')

        if alg is None:
            raise ValueError('"alg" not specified')
        ##################
        # Override Start #
        ##################
        if alg not in MAPPING:
            raise ValueError('"alg" not supported')

        # c = JWSCore(alg, key, protected, self.objects.get('payload'), self.allowed_algs)
        signing_data = _create_signing_data(
            p,
            self.objects.get('payload'),
            MAPPING[alg].algorithm,
        )
        # sig = c.sign()
        sig = key.sign(
            signing_data,
            mechanism=MAPPING[alg].mechanism,
        )
        o = {
            'signature': sig,
            'valid': True,
        }
        ################
        # Override End #
        ################

        if protected:
            o['protected'] = jws.json_encode(p)
        if header:
            o['header'] = h

        if 'signatures' in self.objects:
            self.objects['signatures'].append(o)
        elif 'signature' in self.objects:
            self.objects['signatures'] = []
            n = {'signature': self.objects.pop('signature')}
            if 'protected' in self.objects:
                n['protected'] = self.objects.pop('protected')
            if 'header' in self.objects:
                n['header'] = self.objects.pop('header')
            if 'valid' in self.objects:
                n['valid'] = self.objects.pop('valid')
            self.objects['signatures'].append(n)
            self.objects['signatures'].append(o)
        else:
            self.objects.update(o)
            self.objects['b64'] = b64


class SDJWTIssuer(sd_jwt_i.SDJWTIssuer):
    def _create_signed_jws(self):
        """
        Create the SD-JWT.

        If serialization_format is "compact", then the SD-JWT is a JWT (JWS in compact serialization).
        If serialization_format is "json", then the SD-JWT is a JWS in JSON serialization. The disclosures in this case
        will be added in a separate "disclosures" property of the JSON.

        Overrides
        https://github.com/openwallet-foundation-labs/sd-jwt-python/blob/v0.10.3/src/sd_jwt/issuer.py#L159-L194
        """
        ##################
        # Override Start #
        ##################
        self.sd_jwt = JWS(payload=json.dumps(self.sd_jwt_payload, separators=(',', ':'), sort_keys=True))

        # Assemble protected headers starting with default
        _protected_headers = {"alg": self._sign_alg, "typ": self.SD_JWT_HEADER}
        # override if any
        _protected_headers.update(self._extra_header_parameters)

        self.sd_jwt.add_signature(
            key=self._issuer_key,
            alg=self._sign_alg,
            protected=_protected_headers,
        )

        ################
        # Override End #
        ################

        self.serialized_sd_jwt = self.sd_jwt.serialize(compact=(self._serialization_format == "compact"))

        # If serialization_format is "json", then add the disclosures to the JSON.
        # There does not seem to be a straightforward way to do that with the library
        # other than JSON-decoding the JWS and JSON-encoding it again.
        if self._serialization_format == "json":
            jws_content = json.loads(self.serialized_sd_jwt)
            jws_content[self.JWS_KEY_DISCLOSURES] = [d.b64 for d in self.ii_disclosures]
            self.serialized_sd_jwt = json.dumps(jws_content)
