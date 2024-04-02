# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Tests for Issuance flow using pytest & starlette / fastapi
Uses the issuer DB, depends on environment being set up by the test_system
"""

import os
import json
import urllib.parse
import datetime
import uuid
import re
import typing
from functools import cache
import pytest
import time

from fastapi.testclient import TestClient
from jwcrypto import jwt
import dotenv

from common import verifiable_credential as vc
from common import parsing, jwt_utils
from common import credential_offer as co
import common.config
from common.model import openid4vc as cr
from common.model import ietf
import common.db.postgres as db
import common.key_configuration as key

import issuer.test.hardcoded_creds as dummy
from issuer.route.generic_issuer import router as generic_router
from issuer.route.admin import router as admin_router
from issuer.db.credential import CredentialStatus
import issuer.config as conf
import issuer.timeout as timeout

JSON_REQUEST_HEADER_JSON = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}


def t_config() -> conf.IssuerConfig:
    """
    Overriding Configuration injection function with parameters
    """
    envs = dotenv.dotenv_values(".env")

    config = conf.IssuerConfig()
    config.external_url = os.getenv("TEST_ISSUER", "https://localhost:8000")
    config.registry_key_url = os.getenv("TEST_REGISTRY_BASE", "https://localhost:8010")
    config.registry_key_api_key = envs['REGISTRY_BASE_API_KEY']
    config.registry_revocation_url = os.getenv("TEST_REGISTRY_REVOCATION", "https://localhost:8011")
    config.registry_revocation_api_key = envs['REGISTRY_REVOCATION_API_KEY']
    # Template
    config.template_directory = "test_system/files"
    # Source the environment variables from .env file
    # Load the status list form correct .env, can not be injected using pytest.ini
    config.load_status_list_config(json.loads(envs['STATUS_LIST_CONFIG']))
    return config


def t_session(config: common.config.inject_db_config) -> typing.Generator[db.Session, None, None]:
    """
    Override function Database Injection using the docker compose issuer postgres db
    """
    db_host = os.getenv("ISSUER_DB_HOST", "localhost")
    session = db.session(
        db_connection_string=f"postgresql://postgres:mysecretpassword@{db_host}:5434/issuer",
        db_schema="openid4vc",
    )
    try:
        yield session
    finally:
        session.close()


@cache
def t_key_inject() -> key.KeyConfiguration:
    """
    Override function for key configuration, using the path for local execution as created by setup bash script
    """
    return key.KeyConfiguration.load(key_folder="cert/issuer")


@cache
def t_hsm_inject() -> key.KeyConfiguration:
    """
    Override function for key configuration, using the path for local execution as created by setup bash script
    """
    return key.HardwareSecurityModuleKeyConfiguration(
        library_path="./libsofthsm2.so",
        token_label="dev-token",
        user_pin="1234",
        key_label="dev-issuer",
        signing_algorithm="ES512",
    )


@pytest.fixture()
def key_configuration() -> key.KeyConfiguration:
    yield key.KeyConfiguration.load(key_folder="cert/issuer")


@pytest.fixture(params=[t_key_inject, t_hsm_inject])
def client(request: pytest.FixtureRequest) -> TestClient:
    from issuer.issuer import app, openid_app

    client = TestClient(app, headers={"x-api-key": "tergum_dev_key"})
    app.dependency_overrides[db.env_session] = t_session
    openid_app.dependency_overrides[db.env_session] = t_session
    app.dependency_overrides[key.get_key_configuration] = request.param
    openid_app.dependency_overrides[key.get_key_configuration] = request.param
    app.dependency_overrides[conf.IssuerConfig] = t_config
    openid_app.dependency_overrides[conf.IssuerConfig] = t_config
    yield client
    client.close()


@pytest.fixture(autouse=True)
def restore_metadata(client: TestClient):
    """Save and restore the metadata"""
    response = client.get("/.well-known/openid-credential-issuer")
    assert response.status_code == 200, f"Metadata should be loaded - {response.text}"
    old_metadata = response.json()
    yield
    response = client.post(f"{admin_router.prefix}/metadata", json=old_metadata)
    assert response.status_code == 200, f"If this fails the metadata is now broken {response.text}"


def _parse_deep_link(deeplink: str) -> dict:
    """
    Parses the Payload of the deeplink to a dictionary
    Tests the data in the deeplink
    """
    parsed = urllib.parse.urlparse(deeplink)
    # Offer has to be scheme openid-credential-offer
    # https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#section-4.1.2
    assert parsed.scheme == "openid-credential-offer", "Deeplink must have the openid-credential-offer scheme"
    query = urllib.parse.parse_qsl(parsed.query)
    query_dict = dict(query)
    assert len(query) == len(query_dict), "Parameters should not be encoded twice"
    assert "credential_offer" in query_dict, "credential_offer must be part of the deeplink"
    offer_payload = json.loads(query_dict["credential_offer"])
    # issuer URI, where the receiver of the deep link ought to go fetch the credential.
    assert "credential_issuer" in offer_payload

    # credentials assigned when completing the offer
    assert "credentials" in offer_payload

    # Grant information; AKA How do we tell the issuer who we are
    assert "grants" in offer_payload
    assert "urn:ietf:params:oauth:grant-type:pre-authorized_code" in offer_payload["grants"]
    return offer_payload


def _fetch_oauth2_token(client: TestClient, token_endpoint_uri: str, preauth_code: str) -> dict:
    # Get the authorization token with our pre-authorized code
    response = client.post(token_endpoint_uri, params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": preauth_code})
    assert response.status_code == 200
    oauth2_token = response.json()
    assert "access_token" in oauth2_token
    return oauth2_token


def _generate_holder_proof_token(issuer: str, oauth2_token: dict, key_conf: key.KeyConfiguration) -> str:
    # Build the proof jwt
    proof_jwt_header = {"kid": key_conf.jwk_did, "alg": key_conf.signing_algorithm, "typ": "openid4vci-proof+jwt"}
    proof_jwt_claims = {
        # iss is optional
        "aud": issuer,  # Required
        "iat": round(datetime.datetime.now().timestamp()),  # Required
        "nonce": oauth2_token['c_nonce'],  # Optional, but required for proof verification
    }

    jwt = key_conf.encode_jwt(
        vc.JsonWebTokenBody(
            **proof_jwt_claims,
        ).model_dump(exclude_none=True),
        proof_jwt_header,
    )
    return jwt


def _fetch_openid4vci_credential(client: TestClient, deeplink: str, key_conf: key.KeyConfiguration) -> dict:
    """
    Resolves a deeplink and fetches the credential issued by it. Uses a dummy holder binding
    """
    offer_payload = _parse_deep_link(deeplink)

    pre_auth_info = offer_payload["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    assert "pre-authorized_code" in pre_auth_info and "user_pin_required" in pre_auth_info
    # The pre-authorized_code we need to use as an OAUTH2 bearer token
    preauth_code = pre_auth_info["pre-authorized_code"]

    # Fetch the metadata. A regular user would go to
    # f"{offer_payload['credential_issuer']}/.well-known/openid-configuration"
    openid_configuration = _fetch_issuer_openid_configuration(client)
    token_endpoint = openid_configuration['token_endpoint'].replace(openid_configuration['issuer'], '')

    oauth2_token = _fetch_oauth2_token(client, token_endpoint, preauth_code)

    jwt = _generate_holder_proof_token(openid_configuration['issuer'], oauth2_token, key_conf)

    # Get issued the credentials we have the pre-authorized code for
    response = client.post(
        "/credential",
        headers={"authorization": f"BEARER {oauth2_token['access_token']}"},
        json=cr.CredentialRequest(
            format="jwt_vc_json",
            proof={"proof_type": "jwt", "jwt": jwt},
            credential_definition={"types": offer_payload["credentials"]},
        ).model_dump(exclude_none=True),
    )
    assert response.status_code == 200, response.text

    credential = response.json()
    return credential


def _fetch_issuer_openid_configuration(client):
    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    metadata = response.json()
    return metadata


def _fetch_public_key_set(client: TestClient) -> ietf.JSONWebKeySet:
    response = client.get("/.well-known/jwks.json")
    assert response.status_code == 200
    return ietf.JSONWebKeySet.model_validate(response.json())


def _setup_credential_test(client: TestClient, offer_type: str) -> tuple[vc.OpenID4VerifiableCredentialJWT, key.KeyConfiguration]:
    """Creates a credential offer and reedems the offer"""
    # Get deeplink
    response = None
    match offer_type:
        case "jwt":
            response = client.post(
                "oid4vc/credential/offer",
                json={
                    "metadata_credential_supported_id": "tergum_dummy_jwt",
                    "credential_subject_data": dummy.get_random_degree_credential_data(),
                    "validity_seconds": 604800,
                },
                headers=JSON_REQUEST_HEADER_JSON,
            )
        case "sd_jwt":
            response = client.post(
                "oid4vc/credential/offer",
                json={
                    "metadata_credential_supported_id": "sd_tergum_dummy_jwt",
                    "credential_subject_data": dummy.get_random_degree_credential_data(),
                    "validity_seconds": 604800,
                },
                headers=JSON_REQUEST_HEADER_JSON,
            )
        case "sd_jwt_id":
            response = client.post(
                "oid4vc/credential/offer",
                json={
                    "metadata_credential_supported_id": "sd_tergum_dummy_id_sd_jwt",
                    "credential_subject_data": dummy.get_oid_id_sd_jwt(),
                    "validity_seconds": 604800,
                },
            )
        case _:
            response = None

    assert response.status_code == 200
    deeplink = response.json()["offer_deeplink"]
    assert isinstance(deeplink, str)
    key_configuration: key.KeyConfiguration = client.app.dependency_overrides[key.get_key_configuration]()

    credential = _fetch_openid4vci_credential(
        client,
        deeplink,
        key_configuration,
    )
    return vc.OpenID4VerifiableCredentialJWT.model_validate(credential), key_configuration


@pytest.mark.parametrize(
    "offer_type",
    [
        "jwt",
        "sd_jwt",
        "sd_jwt_id",
    ],
)
def test_openid4vc_dummy_jwt_preauth_flow(client: TestClient, offer_type: str):
    """
    Happy path test for openid4vci pre-auth flow with a dummy jwt
    """
    # Get deeplink
    credential, key_configuration = _setup_credential_test(client, offer_type)

    assert credential.format == "jwt_vc"  # format of the vc
    # assert "c_nonce" in credential # Renewal nonce # TODO -> EID-1253: add c_nonce and renewal
    # Verify signature
    b64_credential = jwt_utils.get_jwt_of_sdjwt(credential.credential)
    public_key = _fetch_public_key_set(client).as_crypto_jwks()
    # Should match the presented public_jwk
    token = jwt.JWT(jwt=b64_credential, key=public_key)
    claims = json.loads(token.claims)
    assert claims['sub'] == key_configuration.jwk_did, "DID we sent should be linked."

    # JWT Tests
    expected_typ = "vc+jwt"
    if jwt_utils.is_sd_jwt(credential.credential):
        # SD-JWT Tests
        expected_typ = "vc+sd-jwt"
        # https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html#name-explicit-typing
        #
        b64_secrets = jwt_utils.get_secrets_of_sdjwt(credential.credential)
        secrets = list(map(parsing.object_from_url_safe, b64_secrets))
        for secret in secrets:
            assert len(secret) == 3, "Secret should always be: ['salt', 'key', value]"
            if "is_over" in secret[1]:
                assert isinstance(secret[2], bool), "Booleans should be booleans after being made secret"

    assert credential.jwt.head.typ == expected_typ


def test_token_errors(client: TestClient):
    """
    This test attempt to get a token while not authorized
    """
    r = client.post("/token", params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": uuid.uuid4()})
    assert r.status_code == 400, "Should not be authorized (and not 500 error) with arbitrary pre-authorized_code"

    r = client.post("/token", params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pin": uuid.uuid4()})
    assert r.status_code == 400, "Should not be authorized (and not 500 error) when only provided pin"

    r = client.post("/token", params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": uuid.uuid4(), "pin": "1234"})
    assert r.status_code == 400, "Should not be authorized (and not 500 error) with inexistet pre-auth code & pin"

    r = client.post("/token", params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code"})
    assert r.status_code == 400, "Should not be authorized (and not 500 error) with no data"

    r = client.post("/token", params={"pre-authorized_code": uuid.uuid4(), "pin": "1234"})
    assert r.status_code == 400, "Should be 400 (and not 500 error) when provided with no grant_type"


def test_set_metadata(client: TestClient):
    """Happy path test for setting well-known openid-credential-issuer metadata"""
    uri: str = "https://issuer"
    """
    A Credential Issuer is identified by a case sensitive URL using
    the https scheme that contains scheme, host and, optionally,
    port number and path components, but no query or fragment components.
    """
    credentials_supported: dict[str, dict] = dict(
        [
            dummy.jwt_credential_info(),
            dummy.sd_jwt_credential_info(),
            dummy.sd_jwt_id_credential_info(),
        ]
    )
    """
    A JSON array containing a list of JSON objects, each of them
    representing metadata about a separate credential type that the
    Credential Issuer can issue. The JSON objects in the array MUST conform
    to the structure of
    https://openid.bitbucket.io/connect/openid-4-verifiable-credential-issuance-1_0.html#credential-metadata-object
    """

    metadata = vc.OpenIDCredentialIssuerData(
        credential_issuer=uri, credential_endpoint=f'{uri}/credential', credentials_supported=credentials_supported, display=[vc.MetadataDisplay(name='Tergum PoC Issuer')]
    )
    response = client.post(f"{admin_router.prefix}/metadata", json=metadata.model_dump(exclude_none=True))
    assert response.status_code == 200, "Should accept the parsed metadata"


def test_health(client: TestClient):
    # Check health
    r = client.get("/health/debug")
    assert r.status_code == 200, f"Service should be healthy {r.text}"
    r = client.get("/health/liveness")
    assert r.status_code == 200, f"Service should be lively {r.text}"
    r = client.get("/health/readiness")
    assert r.status_code == 200, f"Service should be ready {r.text}"


def test_management_id_offer_code(client: TestClient):
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data()}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    offer_response = co.CredentialOfferResponse.model_validate(r.json())
    assert offer_response.management_id, "Should have a management id"
    assert offer_response.offer_deeplink, "Should have an offer"
    assert offer_response.offer_deeplink.startswith("openid-credential-offer"), "Offer should have the correct protocol"
    management_id = str(offer_response.management_id)  # We use the management_id in plain jsons

    ##############
    # Test Offer #
    ##############
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.OFFERED.value, "Status of the credential should be offered"

    r = client.get(f"{generic_router.prefix}/{uuid.uuid4()}")
    assert r.status_code == 404, "Should return 404 when no status found"

    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": True, "purpose": ""})
    assert r.status_code == 200, f"Before the credential has been offered, it should be revokable. Status code: {r.status_code}"
    assert r.json()["credential_status"] == "Revoked", f"Before the credential has been offered, it should be cancellable. Result: {r.text}"

    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": False, "purpose": "revocation"})
    assert r.status_code == 400, f"A revoked offer should not be reofferable. Status code: {r.status_code}"


def test_management_id(client: TestClient):
    """
    Happy Path test for the managment id, with which revocation can be done.
    """
    ###########
    # Issuing #
    ###########
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data()}

    key_configuration = client.app.dependency_overrides[key.get_key_configuration]()

    # Get new Offer
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200
    offer_response = co.CredentialOfferResponse.model_validate(r.json())
    assert offer_response.management_id, "Should have a management id"
    assert offer_response.offer_deeplink, "Should have an offer"
    assert offer_response.offer_deeplink.startswith("openid-credential-offer"), "Offer should have the correct protocol"
    management_id = str(offer_response.management_id)  # We use the management_id in plain jsons
    deeplink = offer_response.offer_deeplink

    offer_payload = _parse_deep_link(deeplink)
    preauth_code = offer_payload["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]["pre-authorized_code"]

    oauth2_token = _fetch_oauth2_token(client, "/token", preauth_code)
    # Reset the offer (if maybe the wallet lost internet or crashed at a bad time)
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.IN_PROGRESS.value, "Status of the credential should reflect that the auth code has been used"
    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": True, "purpose": ""})
    assert r.status_code == 200, "When claiming is in progress, the offer can be reset."
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.OFFERED.value, "After revoking the offer when offered, should be canceled"
    # Fetch The Token again
    oauth2_token = _fetch_oauth2_token(client, "/token", preauth_code)
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.IN_PROGRESS.value, "Status of the credential should reflect that the auth code has been used"

    response = client.get("/.well-known/openid-configuration")
    assert response.status_code == 200
    metadata = response.json()
    jwt = _generate_holder_proof_token(metadata['issuer'], oauth2_token, key_conf=key_configuration)

    # Get the credentials issued to us
    response = client.post(
        "/credential",
        headers={"authorization": f"BEARER {oauth2_token['access_token']}"},
        json={"format": "jwt_vc_json", "proof": {"proof_type": "jwt", "jwt": jwt}, "credential_definition": {"types": offer_payload["credentials"]}},
    )

    assert response.status_code == 200
    credential = response.json()
    assert credential, "We should have the credential now"

    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.ISSUED.value, "Status of the credential be issued"

    ##############
    # Suspension #
    ##############
    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": True, "purpose": "suspension"})
    assert r.status_code == 200, "The credential should be suspendable"
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.SUSPENDED.value, f"Status should reflect suspension {r.text}"

    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": False, "purpose": "suspension"})
    assert r.status_code == 200, f"The credential should be set to not suspended {r.text}"
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.ISSUED.value, f"Status should reflect being not suspended anymore {r.text}"

    ##############
    # Revocation #
    ##############
    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": True, "purpose": "revocation"})
    assert r.status_code == 200, "The credential should be revokable"
    r = client.get(f"{generic_router.prefix}/{management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.REVOKED.value, f"Status should reflect revocation {r.text}"

    r = client.patch(f"{generic_router.prefix}/{management_id}/status", params={"credential_status": True, "purpose": "revocation"})
    assert r.status_code == 400, "After being revoked, can not be revoked again"

    ######################
    # Get Deeplink again #
    ######################

    r = client.get(f"{generic_router.prefix}/{management_id}/offer_deeplink")
    assert r.status_code == 200, "Should find the deeplink"
    assert r.json() == deeplink, "Should return the same deeplink"


def test_get_short_offer(client: TestClient):
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data()}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    offer_response = co.CredentialOfferResponse.model_validate(r.json())
    assert offer_response.management_id, "Should have a management id"

    r = client.get(f"{generic_router.prefix}/{offer_response.management_id}/offer_deeplink/short")
    assert r.status_code == 200, r.text
    short_link = r.json()
    assert isinstance(short_link, str)
    # Remove the external url from the short link. We use the test client which can not be accessed that way
    test_short_link = re.split(r"https?:\/{2}\w+:?\d*", short_link)[-1]
    r = client.get(test_short_link)
    assert r.status_code < 400, test_short_link

    # Using bad data
    short_link_url = "/".join(test_short_link.split("/")[:-1])

    r = client.get(f"{short_link_url}/gugus")
    assert r.status_code == 404, "Should not find anything, when incorrect b64"
    r = client.get(f"{short_link_url}/abc")
    assert r.status_code == 404, "Should not find anything, when incorrect uuid"


def test_redirect_page(client: TestClient):
    # Test is something is returned
    r = client.get("/get-wallet")
    assert r.status_code == 200, "It does not crash"
    assert "html" in r.text


def test_expiration_timer(client: TestClient):
    """
    Tests expiration for offers by nightly timer
    """
    # Register *very* short lived offer
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data(), "offer_validity_seconds": 0}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    expired_offer_response = co.CredentialOfferResponse.model_validate(r.json())

    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data(), "offer_validity_seconds": 1000}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    valid_offer_response = co.CredentialOfferResponse.model_validate(r.json())

    timer_manager = timeout.MidnightCleanupTimer(session_function=t_session)

    # Check Scheduling
    timer_delta = datetime.timedelta(seconds=timer_manager._next_trigger_seconds())
    trigger_datetime = datetime.datetime.now() + timer_delta
    assert trigger_datetime > datetime.datetime.now(), "Next trigger should be in the future"
    assert trigger_datetime < (datetime.datetime.now() + datetime.timedelta(days=1)), "But not 1 full day away"

    # Replace next trigger function to be able to test...
    timer_manager._next_trigger_seconds = lambda: 1
    timer_delta = datetime.timedelta(seconds=timer_manager._next_trigger_seconds())
    assert round(timer_delta.total_seconds()) == 1

    # Check Status
    r = client.get(f"{generic_router.prefix}/{expired_offer_response.management_id}/status")
    assert r.status_code == 200, "Reading the status with a GET should not change the status"
    assert r.json() == CredentialStatus.OFFERED.value, f"Status should be still offered (despite expired in time) {r.text}"

    timer_manager.set_immediate_timer()
    assert timer_manager._timer
    assert timer_manager._timer.is_alive()

    # Wait for the timer
    timer_manager._timer.join()
    # Create a new credential to expire
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data(), "offer_validity_seconds": 0}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    expired_offer_response2 = co.CredentialOfferResponse.model_validate(r.json())

    # Check Status
    # First expired offer should not be valid anymore
    r = client.get(f"{generic_router.prefix}/{expired_offer_response.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.EXPIRED.value, f"Status should reflect expiration {r.text}"

    # Offer with longer expiration should still be valid
    r = client.get(f"{generic_router.prefix}/{valid_offer_response.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.OFFERED.value, f"Status should reflect offered still {r.text}"

    # Second offer should have not run yet and thus not be expired
    r = client.get(f"{generic_router.prefix}/{expired_offer_response2.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.OFFERED.value, f"Status should reflect offered still {r.text}"

    # Wait for the next timer which we did not trigger with set_immediate_timer
    timer_manager._timer.join()
    # Stop timers from running, we're done with the test
    timer_manager.cancel_timer()

    # Check Status
    r = client.get(f"{generic_router.prefix}/{expired_offer_response2.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.EXPIRED.value, f"Status should reflect expiration {r.text}"

    r = client.get(f"{generic_router.prefix}/{valid_offer_response.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.OFFERED.value, f"Status should reflect offered still {r.text}"


def test_expiration_wallet_redeem(client: TestClient):
    """Expiration of offer if the client is trying to redeem a token which is expried"""
    data = {"metadata_credential_supported_id": "tergum_dummy_jwt", "credential_subject_data": dummy.get_random_degree_credential_data(), "offer_validity_seconds": 0}
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    expired_offer_response = co.CredentialOfferResponse.model_validate(r.json())

    offer_payload = _parse_deep_link(expired_offer_response.offer_deeplink)

    pre_auth_info = offer_payload["grants"]["urn:ietf:params:oauth:grant-type:pre-authorized_code"]
    assert "pre-authorized_code" in pre_auth_info and "user_pin_required" in pre_auth_info
    # The pre-authorized_code we need to use as an OAUTH2 bearer token
    preauth_code = pre_auth_info["pre-authorized_code"]
    # Wait a small amount to ensure that 1 second has indeed passed
    time.sleep(1)
    # Fetch the metadata. A regular user would go to
    # f"{offer_payload['credential_issuer']}/.well-known/openid-configuration"
    openid_configuration = _fetch_issuer_openid_configuration(client)
    token_endpoint = openid_configuration['token_endpoint'].replace(openid_configuration['issuer'], '')
    response = client.post(token_endpoint, params={"grant_type": "urn:ietf:params:oauth:grant-type:pre-authorized_code", "pre-authorized_code": preauth_code})
    assert response.status_code == 400, "Should not succeed. If succcess check if sleep time is too short"
    assert "expired" in response.text.lower(), response.text

    # Check Status
    r = client.get(f"{generic_router.prefix}/{expired_offer_response.management_id}/status")
    assert r.status_code == 200, "Should find the status"
    assert r.json() == CredentialStatus.EXPIRED.value, f"Status should reflect expiration {r.text}"


def test_valid_from_until(client: TestClient):
    valid_from = "2024-01-01T00:00:00+00:00"
    valid_until = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(minutes=5)
    data = {
        "metadata_credential_supported_id": "tergum_dummy_jwt",
        "credential_subject_data": dummy.get_random_degree_credential_data(),
        "offer_validity_seconds": 1000,
        "credential_valid_from": valid_from,
        "credential_valid_until": valid_until.isoformat(),
    }
    r = client.post(f"{generic_router.prefix}/offer", json=data)
    assert r.status_code == 200, r.text
    offer_response = co.CredentialOfferResponse.model_validate(r.json())
    deeplink = offer_response.offer_deeplink
    assert isinstance(deeplink, str)
    key_configuration = client.app.dependency_overrides[key.get_key_configuration]()

    credential_raw = _fetch_openid4vci_credential(
        client,
        deeplink,
        key_configuration,
    )
    # Check VC
    credential = vc.OpenID4VerifiableCredentialJWT.model_validate(credential_raw)
    jwt_body = credential.jwt.body
    assert jwt_body.iat, "Issued At should be set"
    assert jwt_body.exp, "Expires should be set"
    assert jwt_body.exp == round(valid_until.timestamp()), "Expires should be set to valid_until"
    assert jwt_body.vc.validFrom, "Valid From should be set"
    assert jwt_body.vc.validFrom == valid_from
    assert jwt_body.vc.validUntil, "Valid Until should be set"
    assert jwt_body.vc.validUntil == valid_until.isoformat()
    assert jwt_body.vc.is_date_valid(), "VC should be in a valid timespan"
