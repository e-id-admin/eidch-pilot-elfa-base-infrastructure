# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
import json
import uuid
import datetime

from httpx import Response
from fastapi import status

import pytest
from deepdiff import DeepDiff
from jwcrypto import jwt, jwk


import common.verifiable_credential as vc
from common import jwt_utils
import common.model.dif_presentation_exchange as dif
import common.test_helpers.wallet_helper as wh
import issuer.test.hardcoded_creds as dummy
import verifier.test_verifier.hard_coded as hc
import verifier.models

from test_system.test_environment import (
    client_admin,
    client_issuer,
    client_verifier,
    client_registry_base,
    client_registry_revocation,
    JSON_REQUEST_HEADER_JSON,
    root_path,
)


def test_health():
    # Check health endpoints
    for client in [client_admin, client_issuer, client_verifier, client_registry_base, client_registry_revocation]:
        r = client.get("/health/debug")
        assert r.status_code == 200, f"Service {client.base_url} should be healthy {r.text}"
        r = client.get("/health/liveness")
        assert r.status_code == 200, f"Service {client.base_url} should be lively {r.text}"
        r = client.get("/health/readiness")
        assert r.status_code == 200, f"Service {client.base_url} should be ready {r.text}"


# Fetcher for Testdata
def _get_test_data(id: str) -> dict:
    with open(os.path.join(root_path, 'files', f'{id}.json')) as f:
        test_data = json.load(f)
    return test_data


# Get Test Metadata for issuer
issuer_metadata = _get_test_data("issuer_metadata")


@pytest.fixture(scope="module", autouse=True)
def setup():
    # Initialize an issuer & registry
    issuer_jwks = client_issuer.get("/.well-known/jwks.json").json()
    r = client_admin.put("/issuer", json=issuer_jwks, headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, "Creating issuer should succeed"
    issuer_base_registry_data: dict = r.json()
    assert issuer_base_registry_data.get("id", "") != "", "Issuer ID should be allocated by the base registry"
    r = client_admin.put(f"/issuer/{issuer_base_registry_data['id']}/status-list", headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, "Creation of status_list should be succeed"
    issuer_status_list_data: dict = r.json()
    assert issuer_status_list_data.get("id", "") != "", "Statuslist ID should be allocated by the revocation registry"
    r = client_issuer.patch("/admin/status-list")
    assert r.status_code == 200, "Update should succeed"

    # Set Metadata for issuer
    r = client_issuer.post("/oid4vc/admin/metadata", json=issuer_metadata, headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, "Metadata upload should succeed"


@pytest.mark.order(0)
def test_issuer_initialization():
    """
    Tests if the issuer is initialized correctly.
    While doing so sets the Metadata for the issuer working
    together with the local docker web wallet.
    """

    r = client_issuer.get("/admin/issuer_id")
    assert r.status_code == 200, "Issuer to base registry must be initialized"
    id = r.json()
    assert id != "", "Issuer to base registry must be initialized"
    r = client_issuer.get("/admin/status-list")
    assert r.status_code == 200, "Revocation Registry must be initialized"
    status_lists = r.json()
    assert status_lists != "", "Revocation Registry must be initialized"
    assert len(status_lists) == 2, "Should have two status lists"
    assert isinstance(status_lists, list), "Should be a list of status list configurations"
    purposes = {sl['purpose'] for sl in status_lists}
    assert 'revocation' in purposes
    assert 'suspension' in purposes
    ###############
    # Base Registry
    r = client_registry_base.get(f"/issuer/{id}/.well-known/openid-configuration")
    assert r.status_code == 200
    issuer_oid_conf = r.json()
    assert "jwks_uri" in issuer_oid_conf
    assert issuer_oid_conf['issuer'] == id
    jwks_url = f"/issuer/{id}/.well-known/jwks.json"
    assert issuer_oid_conf['jwks_uri'].endswith(jwks_url)
    r = client_registry_base.get(jwks_url)
    assert r.status_code == 200
    jwks = r.json()
    assert "keys" in jwks
    assert len(jwks['keys']) > 0
    keys = jwk.JWKSet.from_json(r.text)
    ###############
    # Revocation Registry
    r = client_registry_revocation.get(f"/issuer/{id}/status-list")
    assert r.status_code == 200
    status_lists = r.json()
    assert len(status_lists) > 0
    r = client_registry_revocation.get(f"/issuer/{id}/status-list/{status_lists[0]}")
    assert r.status_code == 200
    status_list_jwt = r.json()
    token = jwt.JWT(jwt=status_list_jwt, key=keys)
    claims = json.loads(token.claims)
    assert "encodedList" in claims['vc']['credentialSubject']
    assert id in claims['iss']
    ###############
    # Issuer Metadata
    # Get issuer metadata
    r = client_issuer.get("/.well-known/openid-credential-issuer", headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, "Metadata upload should succeed"
    metadata_from_issuer = r.json()

    # Compare with dummy Metadata for issuer
    diff = DeepDiff(metadata_from_issuer, issuer_metadata, ignore_order=True)
    # TODO -> EID-1237: Make output readable
    assert not diff, f"Metadata missmatch. Diff: {diff}"


def _call_generic_change_credential_status(management_id: str, purpose: str, value: bool = True) -> str:
    revocation_response = client_issuer.patch(
        f"oid4vc/credential/{management_id}/status", params={"credential_status": value, "purpose": purpose}, headers=JSON_REQUEST_HEADER_JSON
    )
    assert revocation_response.status_code == 200, f"Change status of {management_id} to {value}, {revocation_response.text}"

    return revocation_response.text


def _call_generic_credential_status(
    management_id: str,
) -> str:
    status_response = client_issuer.get(f"oid4vc/credential/{management_id}/status", headers=JSON_REQUEST_HEADER_JSON)
    assert status_response.status_code == 200

    return status_response.json()


def _call_generic_credential_offer(
    metadata_credential_supported_id: str,
    credential_subject_data: dict = {},
    pin: str | None = None,
    validity_seconds: int = 604800,
) -> Response:
    offer_response = client_issuer.post(
        "oid4vc/credential/offer",
        json={
            "metadata_credential_supported_id": metadata_credential_supported_id,
            "credential_subject_data": credential_subject_data,
            "pin": pin,
            "offer_validity_seconds": validity_seconds,
        },
        headers=JSON_REQUEST_HEADER_JSON,
    )
    assert offer_response.status_code == 200, f"Offer went awry. {offer_response.text}"
    offer_response_json = offer_response.json()

    assert "management_id" in offer_response_json, "Expected a management id in offer."
    assert offer_response_json["management_id"], "Expected a management id in offer to be not empty."
    assert "offer_deeplink" in offer_response_json, "Expected a deeplink in offer."
    assert offer_response_json["offer_deeplink"], "Expected a deeplink in offer to be not empty."

    return offer_response


def _generic_issue_jwt_credential() -> tuple[vc.JsonWebTokenBodyVCData, str]:
    """Tests issuing a pre-authorized jwt credential from generic issuer to wallet."""
    # Create Offer on issuer
    offer_response_json = _call_generic_credential_offer("tergum_dummy_jwt", credential_subject_data=_get_test_data("degree_credential_offer_data")).json()
    assert _call_generic_credential_status(offer_response_json['management_id']) == "Offered"

    # Redeem offer with wallet
    credential, jwt = wh.wallet_redeem_offer(offer_response_json["offer_deeplink"])
    credential = vc.JsonWebTokenBodyVCData.model_validate(credential)
    assert _call_generic_credential_status(offer_response_json['management_id']) == "Issued"

    # Verify VC
    status_code, verification_process_id = _verify_credential()
    assert status_code == status.HTTP_200_OK
    _check_verification_process_status(verification_process_id, verifier.models.VerificationStatus.SUCCESS)

    # Suspend VC
    _call_generic_change_credential_status(offer_response_json['management_id'], 'suspension', True)
    assert _call_generic_credential_status(offer_response_json['management_id']) == "Suspended"

    # Verify VC
    status_code, verification_process_id = _verify_credential()
    _check_verification_process_status(verification_process_id, verifier.models.VerificationStatus.FAILED)
    assert status_code == status.HTTP_400_BAD_REQUEST

    # UnSuspend VC
    _call_generic_change_credential_status(offer_response_json['management_id'], 'suspension', False)
    assert _call_generic_credential_status(offer_response_json['management_id']) == "Issued"

    # Verify VC
    status_code, verification_process_id = _verify_credential()
    assert status_code == status.HTTP_200_OK
    _check_verification_process_status(verification_process_id, verifier.models.VerificationStatus.SUCCESS)

    # Revoke VC
    _call_generic_change_credential_status(offer_response_json['management_id'], 'revocation', True)
    assert _call_generic_credential_status(offer_response_json['management_id']) == "Revoked"

    # Verify VC
    status_code, verification_process_id = _verify_credential()
    _check_verification_process_status(verification_process_id, verifier.models.VerificationStatus.FAILED)
    assert status_code == status.HTTP_400_BAD_REQUEST

    return jwt


def test_generic_issue_jwt_credential():
    _generic_issue_jwt_credential()


def _issue_jwt_credential() -> tuple[vc.JsonWebTokenBodyVCData, str]:
    """
    Tests issuing a pre-authorized jwt credential from issuer to wallet
    We also deliberatly test it without validity period set
    """
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json={
            "metadata_credential_supported_id": "tergum_dummy_jwt",
            "credential_subject_data": dummy.get_random_degree_credential_data(),
            "validity_seconds": 604800,
        },
        headers=JSON_REQUEST_HEADER_JSON,
    )
    assert r.status_code == 200

    offer_deeplink = r.json()["offer_deeplink"]
    credential, jwt = wh.wallet_redeem_offer(offer_deeplink)
    credential = vc.JsonWebTokenBodyVCData.model_validate(credential)
    _validated_jwt = vc.JsonWebToken.model_validate(vc.JsonWebToken.from_str(jwt))
    assert _validated_jwt.to_raw() == jwt, "The to raw should be the same as the one with which it was created"
    assert credential.is_date_valid(), "JWT date should be valid"
    assert credential.vc.is_date_valid(), "VC date should be valid"
    return credential, jwt


def test_issue_jwt_credential():
    _issue_jwt_credential()


def _create_validity_period() -> tuple[str, str]:
    """Create valid_from & valid_until datetimes for the current day"""
    today = datetime.date.today().isoformat()
    today_midnight = datetime.datetime.fromisoformat(today)
    tomorrow = today_midnight + datetime.timedelta(days=1)
    end_of_today = tomorrow - datetime.timedelta(seconds=1)
    return today_midnight.isoformat(), end_of_today.isoformat()


def _issue_sd_jwt_credential():
    """
    Tests issuing a pre-authorized sd-jwt credential from issuer to wallet
    """

    valid_from, valid_until = _create_validity_period()
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json={
            "metadata_credential_supported_id": "sd_tergum_dummy_jwt",
            "credential_subject_data": dummy.get_random_degree_credential_data(),
            "validity_seconds": 604800,
            "credential_valid_from": valid_from,
            "credential_valid_until": valid_until,
        },
        headers=JSON_REQUEST_HEADER_JSON,
    )
    assert r.status_code == 200, r.text
    offer_deeplink = r.json()["offer_deeplink"]
    try:
        (credential, disclosures), sd_jwt = wh.wallet_redeem_offer(offer_deeplink)
    except Exception as e:
        raise e
    credential = vc.JsonWebTokenBodyVCData.model_validate(credential)

    _check_correct_sd_format = vc.SelectiveDisclosureJsonWebToken.model_validate(vc.SelectiveDisclosureJsonWebToken.from_str(sd_jwt))
    assert _check_correct_sd_format.to_raw() == sd_jwt
    _check_correct_jwt_format = vc.JsonWebToken.model_validate(_check_correct_sd_format.jwt)
    assert _check_correct_jwt_format.to_raw() == jwt_utils.get_jwt_of_sdjwt(sd_jwt)
    credential = _check_correct_sd_format.jwt.body
    assert credential.is_date_valid(), "JWT date should be valid"
    assert isinstance(credential, vc.JsonWebTokenBodyVCData)
    assert credential.vc.is_date_valid(), "VC date should be valid"
    assert credential.vc.validFrom == valid_from, "Valid From should be set"
    assert credential.vc.validUntil == valid_until, "Valid Until should be set"
    return sd_jwt


def test_issue_sd_jwt_credential():
    _issue_sd_jwt_credential()


def _get_request_object() -> tuple[dif.RequestObject, str]:
    # Verifier generates authorization request
    verification_management = _create_verficiation_verification_management()
    response = client_verifier.get(f"/request-object/{verification_management.authorization_request_id}")
    assert response.status_code == 200
    return dif.RequestObject.model_validate_json(response.content), verification_management.authorization_request_id


def _check_verification_process_status(verification_management_id: str, expected_status: verifier.models.VerificationStatus):
    response = client_verifier.get(f"/oid4vp/verification/{verification_management_id}")
    assert response.status_code == 200
    verification_management = verifier.models.VerificationManagement.model_validate_json(response.content)
    assert verification_management.status.value == expected_status.value, f"Expected status {expected_status.value} but got {verification_management.status} with {response.text}"


def test_get_request_object():
    _get_request_object()


def _verify_credential() -> tuple[int, uuid.UUID]:
    verification_type = 1
    verification_management = _create_verficiation_verification_management(verification_type)

    # Get request object url
    response = client_verifier.get(f"/request-object/{verification_management.authorization_request_id}")
    assert response.status_code == 200
    # request_object = dif.RequestObject.model_validate_json(response.content)

    verification_management_id = verification_management.id
    assert uuid.UUID(verification_management_id)
    _check_verification_process_status(verification_management_id, verifier.models.VerificationStatus.PENDING)

    # Verify the credential
    status_code, response = wh.wallet_verify_credential(verification_management.authorization_request_object_uri)
    wallet_verifiy_data = json.loads(response)
    assert 'verifier_metadata' in wallet_verifiy_data, wallet_verifiy_data
    expected_metadata = hc.get_dummy_client_metadata(verification_type).model_dump()
    assert wallet_verifiy_data['verifier_metadata'] == expected_metadata
    return status_code, verification_management_id


def _create_verficiation_verification_management(verification_type: int = 1) -> verifier.models.VerificationManagement:
    presentation_definition = hc.get_presentation_definition(verification_type).model_dump()
    presentation_definition['client_metadata'] = hc.get_dummy_client_metadata(verification_type).model_dump()

    response_create_verification_management = client_verifier.post("/oid4vp/verification", json=presentation_definition)
    assert response_create_verification_management.status_code == status.HTTP_200_OK, response_create_verification_management.text
    return verifier.models.VerificationManagement.model_validate_json(response_create_verification_management.content)


@pytest.mark.parametrize(
    "credential_fn",
    [_issue_sd_jwt_credential, _issue_jwt_credential],
)
def test_verifiable_presentation(credential_fn) -> None:
    """
    Test GET Verifiable Presentation
    """
    credential_fn()
    status_code, verification_management_id = _verify_credential()

    _check_verification_process_status(verification_management_id, verifier.models.VerificationStatus.SUCCESS)

    response = client_verifier.get(f"/oid4vp/verification/{verification_management_id}/response-data")
    assert response.status_code == 200

    _check_verification_process_status(verification_management_id, verifier.models.VerificationStatus.SUCCESS)

    response = client_verifier.get(f"/oid4vp/verification/{verification_management_id}/response-data")
    assert response.status_code == 400

    assert status_code == status.HTTP_200_OK


def set_issuer_metadata(metadata: dict) -> dict:
    """Sets the issuer metadata, returning the previously used metadata"""
    # Load previously used metadata
    r = client_issuer.get("/.well-known/openid-credential-issuer", headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, f"Getting Metadata should succeed {r.text}"
    old_metadata = r.json()
    # set new metadata
    r = client_issuer.post("/oid4vc/admin/metadata", json=metadata, headers=JSON_REQUEST_HEADER_JSON)
    assert r.status_code == 200, f"Setting Metadata should succeed {r.text}"
    return old_metadata


@pytest.fixture(autouse=True)
def test_setup_teardown():
    # Before test
    old_metadata = set_issuer_metadata(issuer_metadata)
    yield  # Return
    _ = set_issuer_metadata(old_metadata)
    wh.delete_all_test_credentials()
