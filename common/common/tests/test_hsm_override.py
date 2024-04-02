# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""HSM Override Tests. Require Softhsm to work"""

import ssl
import json
import os
import pytest
import pkcs11
import pkcs11.util.ec
import jwcrypto.jwk as jwk
import jwcrypto.jwt as jwt
import jwcrypto.common as jwcommon
import common.hsm.override as ovr


@pytest.fixture
def hsm_session() -> pkcs11.Session:
    library_location = os.environ.get('HSM_LIBRARY', os.path.abspath("./libsofthsm2.so"))
    lib = pkcs11.lib(library_location)
    token = lib.get_token(token_label=os.environ.get('HSM_TOKEN', "dev-token"))
    hsm_session = token.open(user_pin=os.environ.get('HSM_PIN', "1234"))
    yield hsm_session
    hsm_session.close()


@pytest.fixture
def hsm_private_key(hsm_session: pkcs11.Session) -> pkcs11.PrivateKey:
    private_key: pkcs11.PrivateKey = hsm_session.get_key(label=os.environ.get('HSM_LABEL', "dev-issuer"), object_class=pkcs11.constants.ObjectClass.PRIVATE_KEY)
    yield private_key


@pytest.fixture
def hsm_public_key(hsm_session: pkcs11.Session) -> pkcs11.PublicKey:
    public_key: pkcs11.PublicKey = hsm_session.get_key(label=os.environ.get('HSM_LABEL', "dev-issuer"), object_class=pkcs11.constants.ObjectClass.PUBLIC_KEY)
    yield public_key


@pytest.fixture
def public_jwk(hsm_public_key: pkcs11.PublicKey) -> jwk.JWK:
    pk = pkcs11.util.ec.encode_ec_public_key(hsm_public_key)
    pem = ssl.DER_cert_to_PEM_cert(pk)
    pem = pem.replace("CERTIFICATE-----", "PUBLIC KEY-----")
    public_jwk = jwk.JWK.from_pem(pem.encode())
    yield public_jwk


@pytest.fixture
def payload() -> str:
    payload = {"hello": "world"}
    data = json.dumps(payload, separators=(',', ':'), sort_keys=True)
    yield data


@pytest.mark.parametrize("alg", ["ES512"])
def test_hsm_signing(hsm_private_key: pkcs11.PrivateKey, hsm_public_key: pkcs11.PublicKey, payload: str, alg: str):
    """Tests if signing and verifying works"""
    signature = hsm_private_key.sign(
        payload,
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    )
    assert hsm_public_key.verify(
        payload,
        signature,
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    )

    data = ovr._create_signing_data({"alg": alg, "typ": "vc+jwt"}, payload, ovr.MAPPING[alg].algorithm)
    signature = hsm_private_key.sign(
        data,
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    )

    assert hsm_public_key.verify(
        data,
        signature,
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    ), "Signature from emulate core processing should be verifiable"

    sig = ovr.JWS(payload)
    sig.add_signature(hsm_private_key, alg, protected={"alg": alg, "typ": "vc+jwt"})

    assert hsm_public_key.verify(
        data,
        sig.objects['signature'],
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    ), "Signature from add_signature should be verifiable"

    token = sig.serialize(compact=True)
    protected, claims, b64sig = token.split(".")

    assert hsm_public_key.verify(
        data,
        jwcommon.base64url_decode(b64sig),
        mechanism=pkcs11.mechanisms.Mechanism.ECDSA,
    ), "Signature from token should be verifiable"


@pytest.mark.parametrize("alg", ["ES512"])
def test_create_jwt(hsm_private_key: pkcs11.PrivateKey, public_jwk: jwk.JWK, payload: str, alg: str):
    """Creates a JWT and tries to validate it with the public jwk"""
    sig = ovr.JWS(payload)
    sig.add_signature(hsm_private_key, alg, protected={"alg": alg, "typ": "vc+jwt"})
    token = sig.serialize(compact=True)
    assert token.count(".") == 2, f"Ought to be a valid jwt {token}"

    loaded_token = jwt.JWT(jwt=token)

    loaded_token.validate(public_jwk)


@pytest.mark.parametrize("alg", ["ES512"])
def test_create_sd_jwt(hsm_private_key: pkcs11.PrivateKey, public_jwk: jwk.JWK, payload: str, alg: str):
    """creates a SD-JWT and tries to validate it with the public jwk"""
    {"alg": "ES512", "typ": "vc+jwt"}
    issuer = ovr.SDJWTIssuer(
        user_claims=json.loads(payload),
        issuer_key=hsm_private_key,
        sign_alg=alg,
        extra_header_parameters={"typ": "vc+sd-jwt"},
    )
    token = issuer.sd_jwt_issuance

    loaded_token = jwt.JWT(jwt=token.split("~")[0])

    loaded_token.validate(public_jwk)
