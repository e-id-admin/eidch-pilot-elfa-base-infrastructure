# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Test for basic operations of base registry"""

import typing
import uuid
import json
import contextlib

import pytest
import dotenv
from jwcrypto import jwk, jwt

from fastapi.testclient import TestClient

import common.db.postgres as db
from common.db.model.public_key import TrustedIssuer
from registry_base.registry import app
import registry_base.config as conf
import common.config as common_conf


def t_config() -> typing.Generator[conf.RegistryBaseConfig, None, None]:
    """Override for Base Registry Config"""
    envs = dotenv.dotenv_values(".env")
    config = conf.RegistryBaseConfig()
    config.api_key = envs['REGISTRY_BASE_API_KEY']
    config.enable_debug_mode = True
    yield config


def t_session() -> typing.Generator[db.Session, None, None]:
    """
    Override function Database Injection using the docker compose base registry postgres db
    """
    session = db.session(
        db_connection_string="postgresql://postgres:mysecretpassword@localhost:5435/registry",
        db_schema="openid4vc",
    )
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(scope="module")
def client() -> TestClient:
    envs = dotenv.dotenv_values(".env")
    client = TestClient(app, headers={"x-api-key": envs['REGISTRY_BASE_API_KEY']})
    app.dependency_overrides[db.env_session] = t_session
    app.dependency_overrides[conf.RegistryBaseConfig] = t_config
    app.dependency_overrides[common_conf.Config] = t_config
    # Injected config & injected specialized config are not the same override :-(
    yield client
    client.close()


@pytest.fixture()
def issuer_and_key() -> tuple[uuid.UUID, jwk.JWK]:
    """Create a new Issuer in the base registry and return its id with the matching private key"""
    cm_session = contextlib.contextmanager(t_session)
    with cm_session() as session:
        key = jwk.JWK.generate(kty="EC", crv="P-256")
        issuer = TrustedIssuer(
            id=uuid.uuid4(),
            public_key_set={"keys": [key.export_public(as_dict=True)]},
            nonce=uuid.uuid4(),
        )
        session.add(issuer)
        session.commit()
        yield (issuer.id, key)
        session.refresh(issuer)
        session.delete(issuer)
        session.commit()


def create_jwt(
    key: jwk.JWK,
    payload: dict,
    subject: str = None,
    nonce: str = None,
    signing_algorithm: str = "ES256",
) -> str:
    """
    JWT Signed by the issuer; for a very simplistic VC
    """
    # TODO -> EID-1249: Consider how to remove this and use the VC Builder instead?
    # Create JWT
    # Data to identify towards base registry
    body_data = {}
    if nonce:
        body_data['nonce'] = nonce
    if subject:
        body_data['sub'] = subject
    body_data.update(payload)
    token = jwt.JWT(header={"alg": signing_algorithm}, claims=body_data)
    token.make_signed_token(key)
    return token.serialize()


def _get_registered_issuer(client: TestClient) -> list[str]:
    """get Issuer(s) present in DB. At least one should exist from setup_environment.sh"""
    r = client.get("/issuers")
    assert r.status_code == 200, r.text
    return r.json()


def test_fetching_issuer_info(client: TestClient):
    """Happy path test for all get endpoints, correlating data"""
    issuers = _get_registered_issuer(client)
    for issuer in issuers:
        route_base = f"/issuer/{issuer}"
        r = client.get(route_base)
        assert r.status_code == 200, r.text
        issuer_data = r.json()
        r = client.get(f"{route_base}/nonce")
        assert r.status_code == 200, r.text
        assert issuer_data['nonce'] == r.json()
        r = client.get(f"{route_base}/.well-known/jwks.json")
        assert r.status_code == 200, r.text
        assert issuer_data['public_key_set'] == r.json()
        # TODO Add test once /.well-known/openid-configuration is implemented


@pytest.mark.parametrize(
    "issuer_id,expected_status_code",
    [
        ("deadbeef-dead-dead-dead-deaddeafbeef", 404),
        ("InvalidUUID", 422),
    ],
)
def test_faulty_get(client: TestClient, issuer_id: str, expected_status_code: int):
    """Tests that the service returns nicely 404 / 422 instead of crashing with bognus input"""

    def get(route_addon: str):
        r = client.get(f"/issuer/{issuer_id}{route_addon}")
        assert r.status_code == expected_status_code, r.text()

    get("")
    get("/nonce")
    get("/.well-known/jwks.json")


def test_key_update(client: TestClient, issuer_and_key: tuple[uuid.UUID, jwk.JWK]):
    """Tests updating of the issuer key including unauthorized requests & replay attack"""
    issuer_id, key = issuer_and_key
    issuer_id = str(issuer_id)  # UUID to String
    route_base = f"/issuer/{issuer_id}"

    def update_keys(update_jwt: str):
        return client.patch(
            route_base,
            data=json.dumps({"update_jwt": update_jwt}),
        )

    # Test Test Initialization
    r = client.get(route_base)
    assert r.status_code == 200, r.text

    new_key = jwk.JWK.generate(kty="EC", crv="P-256")
    # TEST: Wrong payload
    r = update_keys("foobar")
    assert r.status_code == 401, r.text

    # Prepare Update JWT
    payload = {
        "jwks": {
            "keys": [
                key.export_public(as_dict=True),
                new_key.export_public(as_dict=True),
            ]
        }
    }
    update_jwt = create_jwt(key, payload, issuer_id)

    # TEST: Missing Nonce
    r = client.patch(route_base, data=json.dumps({"update_jwt": update_jwt}))
    assert r.status_code == 401, r.text

    # TEST: Wrong Nonce
    update_jwt = create_jwt(key, payload, issuer_id, nonce="deadbeef-dead-dead-dead-deaddeafbeef")
    r = update_keys(update_jwt)
    assert r.status_code == 401, r.text

    # TEST: Wrong Key
    nonce = _get_nonce(client, route_base)
    update_jwt = create_jwt(new_key, payload, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 401, r.text

    # TEST: Bothering the server with wrong updates does not change the nonce
    new_nonce = _get_nonce(client, route_base)
    assert nonce == new_nonce, "A update resulting in an error should not change the nonce"

    # TEST: Correct Update
    update_jwt = create_jwt(key, payload, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 200, r.text

    # Check if updated
    r = client.get(f"{route_base}/.well-known/jwks.json")
    assert r.status_code == 200, r.text
    key_list = r.json()['keys']
    assert key.export_public(as_dict=True) in key_list
    assert new_key.export_public(as_dict=True) in key_list

    # TEST: New Nonce - cant resend / replay attack
    update_jwt = create_jwt(key, payload, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 401, r.text

    # TEST: New key is now also correct
    nonce = _get_nonce(client, route_base)

    update_jwt = create_jwt(new_key, payload, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 200, r.text

    # TEST: Old key still correct
    nonce = _get_nonce(client, route_base)

    update_jwt = create_jwt(key, payload, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 200, r.text

    # TEST: Missing update JWKS
    nonce = _get_nonce(client, route_base)
    update_jwt = create_jwt(key, {"Hello": "World"}, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    assert r.status_code == 400, r.text
    assert "Missing JWKS" in r.text, "Should complain about missing JWKS"

    # TEST: Data is not a valid JWKS
    nonce = _get_nonce(client, route_base)
    update_jwt = create_jwt(key, {"jwks": {"Hello": "World"}}, issuer_id, nonce=nonce)
    r = update_keys(update_jwt)
    # Should fail when validating
    assert r.status_code == 422, r.text
    assert "missing" in r.text and "keys" in r.text, "Should point out that the field keys are missing"


def _get_nonce(client, route_base):
    """Gets the currently valid nonce"""
    r = client.get(f"{route_base}/nonce")
    assert r.status_code == 200, r.text
    nonce = r.json()
    return nonce
