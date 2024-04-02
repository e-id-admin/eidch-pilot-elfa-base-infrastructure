# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Testing basic operability of revocation registry using base registry & databases as started in docker compose"""

import typing
import uuid
import json
import contextlib
import os

import pytest
import dotenv
from jwcrypto import jwk

from fastapi.testclient import TestClient
import common.db.postgres as db
from common.db.model.status_list import CredentialStatusList

import registry_revocation.config as conf
from registry_revocation.registry import app
import common.config as common_conf

from registry_base.test_registry_base import issuer_and_key, create_jwt, client as base_reg_client  # noqa: F401 Actually used by pytest


def t_session() -> typing.Generator[db.Session, None, None]:
    """
    Override function Database Injection using the docker compose revocation registry postgres db
    """
    session = db.session(
        db_connection_string="postgresql://postgres:mysecretpassword@localhost:5433/registry",
        db_schema="openid4vc",
    )
    try:
        yield session
    finally:
        session.close()


def t_config() -> conf.RevocationRegistryConfig:
    envs = dotenv.dotenv_values(".env")
    config = conf.RevocationRegistryConfig()
    config.registry_key_url = os.getenv("TEST_REGISTRY_BASE", "https://localhost:8010")
    config.api_key = envs['REGISTRY_REVOCATION_API_KEY']
    return config


def t_config_broken() -> conf.RevocationRegistryConfig:
    envs = dotenv.dotenv_values(".env")
    config = conf.RevocationRegistryConfig()
    # Fail to connect
    config.registry_key_url = "https://localhost:22"
    config.api_key = envs['REGISTRY_REVOCATION_API_KEY']
    return config


@pytest.fixture()
def issuer_ids(base_reg_client: TestClient) -> list[str]:  # noqa: F811 pytest fixture
    r = base_reg_client.get("/issuers")
    yield r.json()


@pytest.fixture()
def client_broken_config() -> TestClient:
    envs = dotenv.dotenv_values(".env")
    client = TestClient(app, headers={"x-api-key": envs['REGISTRY_REVOCATION_API_KEY']})
    app.dependency_overrides[db.env_session] = t_session
    app.dependency_overrides[conf.RevocationRegistryConfig] = t_config_broken
    app.dependency_overrides[common_conf.Config] = t_config_broken
    yield client
    client.close()


@pytest.fixture()
def client() -> TestClient:
    envs = dotenv.dotenv_values(".env")
    client = TestClient(app, headers={"x-api-key": envs['REGISTRY_REVOCATION_API_KEY']})
    app.dependency_overrides[db.env_session] = t_session
    app.dependency_overrides[conf.RevocationRegistryConfig] = t_config
    app.dependency_overrides[common_conf.Config] = t_config
    yield client
    client.close()


@pytest.fixture()
def issuer_and_statuslist_and_key(issuer_and_key: tuple[uuid.UUID, jwk.JWK]) -> tuple[uuid.UUID, uuid.UUID, jwk.JWK]:  # noqa: F811 pytest fixture
    """Create a new Issuer in the base registry and return its id with the matching private key and status list id"""
    cm_session = contextlib.contextmanager(t_session)
    issuer_id, key = issuer_and_key
    with cm_session() as session:
        try:
            status_list = CredentialStatusList(id=uuid.uuid4(), issuer_id=issuer_id, status_credential_jwt="Test", nonce=uuid.uuid4())
            session.add(status_list)
            session.commit()
            yield (issuer_id, status_list.id, key)
        finally:
            session.delete(status_list)
            session.commit()


def test_get_status_list(client: TestClient, issuer_ids: list[str]):
    """Listing status lists belonging to an issuer"""
    assert len(issuer_ids) > 0, "Expecting the setup to have been run"
    for issuer_id in issuer_ids:
        r = client.get(f"/issuer/{issuer_id}/status-list")
        assert r.status_code == 200, r.text
        status_lists = r.json()
        assert len(status_lists) > 0, "Expecting the setup status lists"
        for status_list_id in status_lists:
            r = client.get(f"/issuer/{issuer_id}/status-list/{status_list_id}")
            assert r.status_code == 200, r.text
            r = client.get(f"/issuer/{issuer_id}/status-list/{status_list_id}/nonce")
            assert r.status_code == 200, r.text
            uuid.UUID(r.json())  # nonce should be a uuid

    # Non-Existent issuer
    r = client.get("/issuer/deadbeef-dead-dead-dead-deaddeafbeef/status-list")
    assert r.status_code == 200, r.text
    assert len(r.json()) == 0

    r = client.get("/issuer/deadbeef-dead-dead-dead-deaddeafbeef/status-list/deadbeef-dead-dead-dead-deaddeafbeef")
    assert r.status_code == 404, r.text

    r = client.get(f"/issuer/deadbeef-dead-dead-dead-deaddeafbeef/status-list/{status_list_id}")
    assert r.status_code == 404, r.text

    r = client.get("/issuer/deadbeef-dead-dead-dead-deaddeafbeef/status-list/deadbeef-dead-dead-dead-deaddeafbeef/nonce")
    assert r.status_code == 404, r.text

    # Non-Existent status list
    r = client.get(f"/issuer/{issuer_id}/status-list/deadbeef-dead-dead-dead-deaddeafbeef")
    assert r.status_code == 404, r.text

    r = client.get(f"/issuer/{issuer_id}/status-list/deadbeef-dead-dead-dead-deaddeafbeef/nonce")
    assert r.status_code == 404, r.text


def test_update_status_list(
    client: TestClient,
    issuer_and_statuslist_and_key: tuple[uuid.UUID, uuid.UUID, jwk.JWK],
):
    """Tests most common Happy and non-happy paths for updating status lists"""
    issuer_id, status_list_id, key = issuer_and_statuslist_and_key
    issuer_id = str(issuer_id)
    status_list_id = str(status_list_id)
    url = f"/issuer/{issuer_id}/status-list/{status_list_id}"

    def update_status_list(update_jwt: str):
        return client.patch(url, data=json.dumps({"update_jwt": update_jwt}))

    # TEST: Initialization of test setup
    r = client.get(url)
    assert r.status_code == 200, r.text

    # TEST: Nonsense Payload
    r = client.patch(url, data="foobar")
    assert r.status_code == 422, r.text

    r = update_status_list("foobar")
    assert r.status_code == 401, r.text

    # TEST: Missing Nonce
    dummy_payload = {"jwt_vc": create_jwt(key, {"vc": {"type": "StatusList", "purpose": "revocation"}}, issuer_id)}
    r = update_status_list(create_jwt(key, dummy_payload, issuer_id))
    assert r.status_code == 401, r.text

    # TEST: Wrong Nonce
    r = update_status_list(create_jwt(key, dummy_payload, issuer_id, nonce="deadbeef-dead-dead-dead-deaddeafbeef"))
    assert r.status_code == 401, r.text

    # TEST: Wrong Key
    r = client.get(f"{url}/nonce")
    assert r.status_code == 200, r.text
    nonce = r.json()
    wrong_key = jwk.JWK.generate(kty="EC", crv="P-256")
    r = update_status_list(create_jwt(wrong_key, dummy_payload, issuer_id, nonce))
    assert r.status_code == 401, r.text

    # TEST: Correct Update
    r = update_status_list(create_jwt(key, dummy_payload, issuer_id, nonce))
    assert r.status_code == 200, r.text

    # TEST: new Nonce - can't resend / replay attack
    r = update_status_list(create_jwt(key, dummy_payload, issuer_id, nonce))
    assert r.status_code == 401, r.text
    r = client.get(f"{url}/nonce")
    assert r.status_code == 200, r.text
    nonce = r.json()
    # TEST: New Nonce works
    update_jwt = create_jwt(key, dummy_payload, issuer_id, nonce)
    r = update_status_list(update_jwt)
    assert r.status_code == 200, r.text

    # TEST: Data has been written
    r = client.get(url)
    assert r.status_code == 200, r.text
    assert r.json() == dummy_payload['jwt_vc']


def test_broken_config(
    client_broken_config: TestClient,
    issuer_and_statuslist_and_key: tuple[uuid.UUID, uuid.UUID, jwk.JWK],
):
    """Test with a Revocation Registry using a config pointing to an unavailable Base Registry"""
    issuer_id, status_list_id, key = issuer_and_statuslist_and_key
    issuer_id = str(issuer_id)
    status_list_id = str(status_list_id)
    url = f"/issuer/{issuer_id}/status-list/{status_list_id}"

    r = client_broken_config.get("/health/liveness")
    assert r.status_code == 200, r.text
    r = client_broken_config.get("/health/readiness")
    assert r.status_code == 503, r.text

    # TEST: Correct Update, but broken connection to base registry
    r = client_broken_config.get(f"{url}/nonce")
    assert r.status_code == 200, r.text
    nonce = r.json()
    dummy_payload = {"jwt_vc": create_jwt(key, {"vc": {"type": "StatusList", "purpose": "revocation"}}, issuer_id)}
    r = client_broken_config.patch(url, data=json.dumps({"update_jwt": create_jwt(key, dummy_payload, issuer_id, nonce)}))
    assert r.status_code == 503, r.text
