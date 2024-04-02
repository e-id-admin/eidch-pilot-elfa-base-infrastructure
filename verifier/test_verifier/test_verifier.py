# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Tests Verification Flow
"""

from enum import Enum
import re
import time
import uuid
from unittest import mock

from fastapi import status
from fastapi.testclient import TestClient
from httpx import Response
import httpx
import pytest
import dotenv

from common import jwt_utils, verifiable_credential as vc
from common.model import ietf
from common.model import dif_presentation_exchange as dif
from common.key_configuration import KeyConfiguration

import verifier.exception as err
import verifier.models as model
from verifier.test_verifier import test_data
import verifier.test_verifier.hard_coded as hc
from verifier.config import VerifierConfig

# Imports for mocking

# The key has to match the issued credentials in the test data else verification_management does not work.
key_config = KeyConfiguration(test_data.PUBLIC_KEY, test_data.PRIVATE_KEY, "ES512")
UUID_BASIC_PATTERN = "[0-9a-f]{8}-[0-9a-f]{4}-[0-5][0-9a-f]{3}-[089ab][0-9a-f]{3}-[0-9a-f]{12}"
UUID_PATTERN = f"^{UUID_BASIC_PATTERN}$"
REQUEST_URL_PATTERN = f"http[s]?\:\/\/\S+\/request-object\/({UUID_BASIC_PATTERN})"
RESPONSE_URI_PATTERN = f"^{REQUEST_URL_PATTERN}\/response-data$"
GENERIC_VERIFIER_PREFIX = "/oid4vp/verification"


def _create_vp_token(credential: str, nonce: str) -> bytes:
    vp = vc.JsonWebTokenBodyVCData(
        iss=key_config.jwk_did,
        vp=vc.VerifiablePresentation(
            type="VerifiablePresentation",
            verifiableCredential=[credential],
        ),
        nonce=nonce,
    )
    return key_config.encode_jwt(vp.model_dump(exclude_none=True))


class PredefinedPresentations(Enum):
    ELFA = "elfa"
    UNIVERSITY = "university"


def _create_verification_management_for_predefined_presentation(presentation: PredefinedPresentations, client: TestClient) -> model.VerificationManagement:
    input_descriptors = hc.get_presentation_definition(1 if presentation == PredefinedPresentations.UNIVERSITY else 2).input_descriptors
    presentation_definition = model.PresentationDefinitionRequest(input_descriptors=input_descriptors)
    response_create_verification_management = client.post(f"{GENERIC_VERIFIER_PREFIX}", data=presentation_definition.model_dump_json(exclude={'id'}))
    assert response_create_verification_management.status_code == status.HTTP_200_OK
    return model.VerificationManagement.model_validate_json(response_create_verification_management.content)


@pytest.fixture
def client(request) -> TestClient:
    from verifier.verifier import app, openid_app

    config = VerifierConfig()
    if hasattr(request, 'param'):
        config = request.param
    # General config
    config.external_url = "https://localhost:8001"

    # Dynamic config from .env file
    envs = dotenv.dotenv_values(".env")
    for env, value in envs.items():
        config.__dict__[env] = value

    client = TestClient(app, headers={"x-api-key": "tergum_dev_key"})
    app.dependency_overrides[VerifierConfig] = lambda: config
    openid_app.dependency_overrides[VerifierConfig] = lambda: config
    yield client
    client.close()


@pytest.fixture
def invalid_issuer_client(request) -> TestClient:
    from verifier.verifier import app, openid_app

    config = VerifierConfig()
    if hasattr(request, 'param'):
        config = request.param
    # General config
    config.external_url = "https://localhost:8001"

    # Dynamic config from .env file
    envs = dotenv.dotenv_values(".env")
    for env, value in envs.items():
        config.__dict__[env] = value

    config.filter_allowed_issuers_regex = re.compile("impossible configuration")

    client = TestClient(app, headers={"x-api-key": "tergum_dev_key"})
    app.dependency_overrides[VerifierConfig] = lambda: config
    openid_app.dependency_overrides[VerifierConfig] = lambda: config
    yield client
    client.close()


def _get_verification_predefined_elfa(client: TestClient) -> model.VerificationManagement:
    return _create_verification_management_for_predefined_presentation(PredefinedPresentations.ELFA, client)


def _get_verification_predefined_university(client: TestClient) -> model.VerificationManagement:
    return _create_verification_management_for_predefined_presentation(PredefinedPresentations.UNIVERSITY, client)


def _get_presentation_submission() -> dif.DIFPresentationSubmission:
    """
    Returns a dummy presentation submission.
    """
    return dif.DIFPresentationSubmission(
        id="Fake",
        definition_id="News",
        descriptor_map=[dif.DIFPresentationDescriptor(id="One", format="jwt_vp_json", path_nested=dif.DIFPathNested(path="$.vp.verifiableCredential[0]", format='jwt_vc'))],
    )


def _send_vc_submission(submission_data: dict, authorization_request_id: str, revoked: bool, jwt_valid: bool, client: TestClient) -> Response:
    with (
        mock.patch(
            "verifier.verification.verify_valid_jwt",
            return_value=None,
        ),
        mock.patch(
            "verifier.verification.is_valid_jwt",
            return_value=jwt_valid,
        ),
        mock.patch(
            "httpx.get",
            return_value=Response(
                200,
                content=test_data.ALL_REVOKED_STATUSLIST if revoked else test_data.NOTHING_REVOKED_STATUSLIST,
            ),
        ),
        mock.patch(
            "verifier.verification.jwt_utils.get_jwks",
            return_value=ietf.JSONWebKeySet(keys=[key_config.public_key_as_dto()]),
        ),
    ):
        response = client.post(
            f"/request-object/{authorization_request_id}/response-data",
            headers={'accept': 'application/x-www-form-urlencoded', 'Content-Type': 'application/x-www-form-urlencoded'},
            data=submission_data,
        )
        return response


def _get_auth_request_object(client: TestClient, authorization_request_id: str) -> dif.RequestObject:
    response_request_object = client.get(f"/request-object/{authorization_request_id}")
    assert response_request_object.status_code == status.HTTP_200_OK
    return dif.RequestObject.model_validate_json(response_request_object.content)


def _get_response_data_post_call_data_payload(credential: str, nonce: str):
    return {
        "presentation_submission": _get_presentation_submission().model_dump_json(exclude_none=True),
        "vp_token": _create_vp_token(credential, nonce),
    }


def _send_holder_vc_submission_and_token(authorization_request_id: str, revoked: bool, jwt_valid: bool, credential: str, client: TestClient) -> Response:
    # Get authorization request object
    request_object = _get_auth_request_object(authorization_request_id=authorization_request_id, client=client)
    data = _get_response_data_post_call_data_payload(credential, request_object.nonce)
    return _send_vc_submission(submission_data=data, revoked=revoked, jwt_valid=jwt_valid, authorization_request_id=authorization_request_id, client=client)


def _send_error_submission(authorization_request_id: str, error: str, client: TestClient, error_description: str = None):
    data = {"error": error, "error_description": error_description}
    return _send_vc_submission(submission_data=data, authorization_request_id=authorization_request_id, revoked=False, jwt_valid=True, client=client)


def _assert_verification_management_status(client: TestClient, verification_management_id: str, verification_status: model.VerificationStatus):
    response_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_management_id}")
    assert response_verification_management.status_code == status.HTTP_200_OK
    verification_management = model.VerificationManagement.model_validate_json(response_verification_management.content)
    assert verification_management.status == verification_status


def _assert_authorization_data_status(
    client: TestClient,
    verification_management_id: str,
    expected_error: str | None = None,
):
    response_authentication_data = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_management_id}/response-data")
    assert response_authentication_data.status_code == status.HTTP_200_OK
    authentication_data = model.AuthorizationResponseData.model_validate_json(response_authentication_data.content)
    if expected_error is None:
        assert authentication_data.error_code is None
    else:
        assert authentication_data.error_code == expected_error


"""
Test for generic verifier endpoints
"""


def test_get_verification_data_errors(client):
    # VerificationNotFoundError
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{uuid.uuid4().hex}/response-data")
    assert response_get_verification_management.status_code == status.HTTP_404_NOT_FOUND
    assert response_get_verification_management.json()["detail"].__contains__(err.VerificationNotFoundError.error)

    # VerificationNotFinishedError
    verification_management = _get_verification_predefined_elfa(client)
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_management.id}/response-data")
    assert response_get_verification_management.status_code == status.HTTP_404_NOT_FOUND
    assert response_get_verification_management.json()["detail"].__contains__(err.VerificationNotFinishedError.error)


def test_create_verification(client):
    # With generic templated passed on endpoint call
    credential_id = "ELFA"
    presentation_definition = model.PresentationDefinitionRequest(
        input_descriptors=[
            dif.InputDescriptor(
                id=credential_id,
                format={"jwt_vc": {"alg": "ES512"}},
                constraints=dif.Fields(fields=[dif.Constraint(path=["$.vc.type[*]"], filter=dif.Filter(pattern="ELFA", type="string"))]),
            )
        ],
        client_metadata={"client_name": "Dummy Client", "logo_uri": "Dummy Logo Uri"},
    )
    response = client.post(
        GENERIC_VERIFIER_PREFIX, headers={'accept': 'application/json', 'Content-Type': 'application/json'}, data=presentation_definition.model_dump_json(exclude={'id'})
    )
    assert response.status_code == status.HTTP_200_OK
    verification_management = model.VerificationManagement.model_validate_json(response.content)
    request_object = _get_auth_request_object(authorization_request_id=verification_management.authorization_request_id, client=client)
    assert request_object.presentation_definition.input_descriptors[0].id == credential_id
    assert request_object.client_metadata.client_name == "Dummy Client", "Client metadata should be set"


def test_create_elfa_verification(client):
    # With predefined template
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response_get_verification_management.status_code == status.HTTP_200_OK
    assert model.VerificationManagement.model_validate_json(response_get_verification_management.content).id == verification_predefined_elfa.id
    assert re.match(UUID_PATTERN, verification_predefined_elfa.authorization_request_id)
    assert re.match(UUID_PATTERN, verification_predefined_elfa.id)
    assert re.match(f"^{REQUEST_URL_PATTERN}$", verification_predefined_elfa.authorization_request_object_uri)


def test_create_verification_errors(client):
    # VerificationNotFoundError
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{uuid.uuid4().hex}")
    assert response_get_verification_management.status_code == status.HTTP_404_NOT_FOUND
    assert response_get_verification_management.json()["detail"].__contains__(err.VerificationNotFoundError.error)


def test_get_request_object(client):
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    request_object = _get_auth_request_object(authorization_request_id=verification_predefined_elfa.authorization_request_id, client=client)
    assert re.match(RESPONSE_URI_PATTERN, request_object.response_uri)
    assert request_object.response_mode == "direct_post"


"""
Test for openid verifier endpoints
"""


def test_get_presentation_definition(client):
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    request_object = _get_auth_request_object(authorization_request_id=verification_predefined_elfa.authorization_request_id, client=client)

    response_presentation_definition = client.get(f'/presentation-definition/{request_object.presentation_definition.id}')
    assert response_presentation_definition.status_code == status.HTTP_200_OK
    presentation_definition = dif.PresentationDefinition.model_validate_json(response_presentation_definition.content)
    assert presentation_definition.id == request_object.presentation_definition.id


def test_get_request_object_errors(client):
    # AuthorizationRequestObjectNotFoundError
    response = client.get(f"/request-object/{uuid.uuid4().hex}")
    assert response.status_code == status.HTTP_404_NOT_FOUND
    assert response.json()["error"] == err.AuthorizationRequestObjectNotFoundError.error
    assert response.json()["error_description"] == err.AuthorizationRequestObjectNotFoundError.error_description


def test_verify_presentation_submit_error(client):
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    # Holder submits error e.g. when end user declines the verification request
    holder_rejected = "client_rejected"
    _send_error_submission(authorization_request_id=verification_predefined_elfa.authorization_request_id, client=client, error=holder_rejected)
    _assert_verification_management_status(client=client, verification_management_id=verification_predefined_elfa.id, verification_status=model.VerificationStatus.FAILED)
    _assert_authorization_data_status(client=client, verification_management_id=verification_predefined_elfa.id, expected_error=holder_rejected)


@pytest.mark.parametrize(
    "revoked,jwt_valid,credential",
    [
        (False, True, test_data.UNIVERSITY_SD_JWT),
        (False, True, test_data.UNIVERSITY_JWT),
    ],
)
def test_verify_university_presentation(
    client: TestClient,
    revoked: bool,
    jwt_valid: bool,
    credential: str,
):
    _verify_presentation(revoked=revoked, jwt_valid=jwt_valid, credential=credential, verification_predefined=_get_verification_predefined_university(client=client), client=client)


@pytest.mark.parametrize(
    "revoked,jwt_valid,credential",
    [(False, True, test_data.ELFA_SD_JWT)],
)
def test_verify_elfa_presentation(
    client: TestClient,
    revoked: bool,
    jwt_valid: bool,
    credential: str,
):
    _verify_presentation(revoked=revoked, jwt_valid=jwt_valid, credential=credential, verification_predefined=_get_verification_predefined_elfa(client=client), client=client)


def _verify_presentation(client: TestClient, revoked: bool, jwt_valid: bool, credential: str, verification_predefined: model.VerificationManagement):
    response = _send_holder_vc_submission_and_token(
        authorization_request_id=verification_predefined.authorization_request_id, revoked=revoked, jwt_valid=jwt_valid, credential=credential, client=client
    )
    assert response.status_code == 200, "Should succeed"
    _assert_verification_management_status(client=client, verification_management_id=verification_predefined.id, verification_status=model.VerificationStatus.SUCCESS)
    _assert_authorization_data_status(verification_management_id=verification_predefined.id, client=client)
    response = _send_holder_vc_submission_and_token(
        client=client,
        authorization_request_id=verification_predefined.authorization_request_id,
        revoked=revoked,
        jwt_valid=jwt_valid,
        credential=credential,
    )
    assert response.status_code == 400, "Second time should fail"
    error_body = response.json()
    assert 'error' in error_body and error_body['error'] == "verification_process_closed", "Should only be able to verification once"


@pytest.mark.parametrize(
    "revoked,jwt_valid,credential,assumed_exception_content",
    [
        (True, True, test_data.ELFA_SD_JWT, err.CredentialRevokedError.error_code),
        (False, False, test_data.ELFA_SD_JWT, err.CredentialInvalidError.error_code),
        (False, False, test_data.ELFA_SD_JWT, err.CredentialInvalidError.error_code),
    ],
)
def test_verify_elfa_presentation_errors(
    client: TestClient,
    revoked: bool,
    jwt_valid: bool,
    credential: str,
    assumed_exception_content: str,
):
    _verify_presentation_errors(
        client=client,
        revoked=revoked,
        credential=credential,
        jwt_valid=jwt_valid,
        assumed_exception_content=assumed_exception_content,
        verification_management=_get_verification_predefined_elfa(client=client),
    )


@pytest.mark.parametrize("credential", [test_data.ELFA_SD_JWT])
@pytest.mark.parametrize("revoked", [True, False])
@pytest.mark.parametrize("jwt_valid", [True, False])
def test_verify_elfa_presentation_errors_invalid_issuer(
    invalid_issuer_client: TestClient,
    revoked: bool,
    jwt_valid: bool,
    credential: str,
):
    _verify_presentation_errors(
        client=invalid_issuer_client,
        revoked=revoked,
        credential=credential,
        jwt_valid=jwt_valid,
        assumed_exception_content=err.CredentialInvalidError.error_code,
        verification_management=_get_verification_predefined_elfa(client=invalid_issuer_client),
    )


@pytest.mark.parametrize(
    "revoked,jwt_valid,credential,assumed_exception_content",
    [
        (True, True, test_data.UNIVERSITY_SD_JWT, err.CredentialRevokedError.error_code),
        (False, False, test_data.UNIVERSITY_SD_JWT, err.CredentialInvalidError.error_code),
        (True, True, test_data.UNIVERSITY_JWT, err.CredentialRevokedError.error_code),
        (False, False, test_data.UNIVERSITY_JWT, err.CredentialInvalidError.error_code),
    ],
)
def test_verify_university_presentation_errors(
    client: TestClient,
    revoked: bool,
    jwt_valid: bool,
    credential: str,
    assumed_exception_content: str,
):
    _verify_presentation_errors(
        client=client,
        revoked=revoked,
        credential=credential,
        jwt_valid=jwt_valid,
        assumed_exception_content=assumed_exception_content,
        verification_management=_get_verification_predefined_elfa(client=client),
    )


def _verify_presentation_errors(
    client: TestClient, revoked: bool, jwt_valid: bool, credential: str, assumed_exception_content: str, verification_management: model.VerificationManagement
):
    response = _send_holder_vc_submission_and_token(
        authorization_request_id=verification_management.authorization_request_id, revoked=revoked, jwt_valid=jwt_valid, credential=credential, client=client
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    _assert_verification_management_status(client=client, verification_management_id=verification_management.id, verification_status=model.VerificationStatus.FAILED)
    _assert_authorization_data_status(client=client, verification_management_id=verification_management.id, expected_error=assumed_exception_content)
    response = _send_holder_vc_submission_and_token(
        client=client,
        authorization_request_id=verification_management.authorization_request_id,
        revoked=revoked,
        jwt_valid=jwt_valid,
        credential=credential,
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
    error_body = response.json()
    assert 'error' in error_body and error_body['error'] == "verification_process_closed", "Should only be able to verification once"


def test_changed_keys_error(client):
    # Get injected Verification Management Fixture
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response_get_verification_management.status_code == status.HTTP_200_OK
    verification_management_object = model.VerificationManagement.model_validate_json(response_get_verification_management.content)
    assert model.VerificationManagement.model_validate_json(response_get_verification_management.content).id == verification_predefined_elfa.id
    # Get the Request Object
    request_object = _get_auth_request_object(client=client, authorization_request_id=verification_management_object.authorization_request_id)
    data = {
        "presentation_submission": _get_presentation_submission().model_dump_json(exclude_none=True),
        "vp_token": test_data.BROKEN_TOKEN,
    }
    r = client.post(
        request_object.response_uri,
        headers={'accept': 'application/x-www-form-urlencoded', 'Content-Type': 'application/x-www-form-urlencoded'},
        data=data,
    )
    assert r.status_code == 400, "VP Token should have an error!"
    assert "Failed to fetch Wallet JWKS" in r.json()['additional_error_description'], "Error should have a pointer to where in the verification process getting the JWKS failed"
    assert (
        "Invalid base64-encoded string: number of data characters (46677) cannot be 1 more than a multiple of 4" in r.json()['additional_error_description']
    ), "Detail information what went wrong"


@pytest.mark.parametrize(
    "credential,sd_jwt_ending",
    [
        (test_data.ELFA_SD_JWT, ""),
        (test_data.ELFA_SD_JWT, "~"),
        (test_data.ELFA_SD_JWT, "~~"),
    ],
)
def test_verify_presentation_missing_disclosure(
    credential: str,
    sd_jwt_ending: str,
    client: TestClient,
):
    """Test where the SD-JWT map has a missing disclosure"""
    verification_predefined = _get_verification_predefined_elfa(client=client)
    # Get authorization request object
    request_object = _get_auth_request_object(authorization_request_id=verification_predefined.authorization_request_id, client=client)
    missing_credential = credential[: credential.index("~")] + sd_jwt_ending
    data = {
        "presentation_submission": _get_presentation_submission().model_dump_json(exclude_none=True),
        "vp_token": _create_vp_token(missing_credential, request_object.nonce),
    }

    r = _send_vc_submission(submission_data=data, revoked=False, jwt_valid=True, authorization_request_id=verification_predefined.authorization_request_id, client=client)
    assert r.status_code == 400, "Should not succeed when Presentation is faulty"

    raw_error = r.json()
    error = err.OpenIdError.model_validate(r.json())
    assert error.error == "invalid_request"
    assert 'error_code' in raw_error
    assert raw_error['error_code'] == "credential_missing_data"
    assert "$.vc.credentialSubject.lastName" in error.error_description, "Should contain (at least the first) missing attribute"
    _assert_verification_management_status(
        client=client,
        verification_management_id=verification_predefined.id,
        verification_status=model.VerificationStatus.FAILED,
    )


def test_health(client: TestClient):
    # Check health
    r = client.get("/health/debug")
    assert r.status_code == 200, f"Service should be healthy {r.text}"
    r = client.get("/health/liveness")
    assert r.status_code == 200, f"Service should be lively {r.text}"
    r = client.get("/health/readiness")
    assert r.status_code == 200, f"Service should be ready {r.text}"


def _verifier_ttl(ttl: int) -> VerifierConfig:
    """
    Overriding VerifierConfig with custom ttl, so that it can be validated inside the test
    """
    config = VerifierConfig()
    config.verification_ttl = ttl
    return config


@pytest.mark.parametrize('client', [_verifier_ttl(2)], indirect=True)
def test_verification_request_ttl(client):
    # Create verification request
    verification_predefined_elfa = _get_verification_predefined_elfa(client)
    _assert_verification_management_status(client=client, verification_management_id=verification_predefined_elfa.id, verification_status=model.VerificationStatus.PENDING)

    # Expires response data
    time.sleep(2)

    # Assert that the data has been removed
    response_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response_verification_management.status_code == status.HTTP_404_NOT_FOUND


@pytest.mark.parametrize('client', [_verifier_ttl(3)], indirect=True)
def test_verification_response_data_ttl(client):
    verification_predefined_elfa = _get_verification_predefined_elfa(client)

    # Create verification
    response = _send_holder_vc_submission_and_token(
        client=client,
        authorization_request_id=verification_predefined_elfa.authorization_request_id,
        revoked=False,
        jwt_valid=True,
        credential=test_data.ELFA_SD_JWT,
    )
    assert response.status_code == 200, "Should succeed"

    # Submit response data
    _assert_verification_management_status(client=client, verification_management_id=verification_predefined_elfa.id, verification_status=model.VerificationStatus.SUCCESS)
    response_authentication_data = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}/response-data")
    assert response_authentication_data.status_code == status.HTTP_200_OK

    # Expires response data
    time.sleep(3)

    # Assert that the data and verificaiton has expired
    response = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response.status_code == status.HTTP_404_NOT_FOUND, "Should succeed"
    response_authentication_data = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}/response-data")
    assert response_authentication_data.status_code == status.HTTP_404_NOT_FOUND


def test_get_request_object_without_nonce(client: TestClient):
    verification_predefined = _get_verification_predefined_elfa(client=client)
    data = _get_response_data_post_call_data_payload(test_data.ELFA_SD_JWT, None)
    response = _send_vc_submission(submission_data=data, revoked=False, jwt_valid=True, authorization_request_id=verification_predefined.authorization_request_id, client=client)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == err.MissingNonceError.error
    assert response.json()["error_description"] == err.MissingNonceError.error_description


def test_get_request_object_with_wrong_nonce(client: TestClient):
    verification_predefined = _get_verification_predefined_elfa(client=client)
    request_object = _get_auth_request_object(authorization_request_id=verification_predefined.authorization_request_id, client=client)
    data = _get_response_data_post_call_data_payload(test_data.ELFA_SD_JWT, request_object.nonce + "-test")
    response = _send_vc_submission(submission_data=data, revoked=False, jwt_valid=True, authorization_request_id=verification_predefined.authorization_request_id, client=client)

    assert response.status_code == status.HTTP_400_BAD_REQUEST
    assert response.json()["error"] == err.InvalidNonceError.error
    assert response.json()["error_description"] == err.InvalidNonceError.error_description


@pytest.mark.parametrize('client', [_verifier_ttl(3)], indirect=True)
def test_verification_management_update_ttl(client):
    # Create verification management request
    verification_predefined_elfa = _get_verification_predefined_elfa(client)

    # Assert current expiratrion time
    response = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response.status_code == status.HTTP_200_OK, "Should succeed"
    verification_management = model.VerificationManagement.model_validate_json(response.content)
    assert verification_management.expires_at == verification_predefined_elfa.expires_at, "Expiration time should be the original one"

    # Give the test some time to prevent that the same epoche is used
    time.sleep(1)

    # Submit response data
    response = _send_holder_vc_submission_and_token(
        client=client,
        authorization_request_id=verification_predefined_elfa.authorization_request_id,
        revoked=False,
        jwt_valid=True,
        credential=test_data.ELFA_SD_JWT,
    )

    # Assert updated expiratrion time which is aligned to verification response data
    response_updated = client.get(f"{GENERIC_VERIFIER_PREFIX}/{verification_predefined_elfa.id}")
    assert response.status_code == status.HTTP_200_OK, "Should succeed"
    verification_management_updated = model.VerificationManagement.model_validate_json(response_updated.content)
    assert verification_management_updated.expires_at != verification_predefined_elfa.expires_at, "Expiration time should not be the original one"


@pytest.mark.parametrize('client', [_verifier_ttl(4)], indirect=True)
def test_different_ttl_of_cached_objects(client):
    # Create verification
    original_verification = _get_verification_predefined_elfa(client)
    response = client.get(f"{GENERIC_VERIFIER_PREFIX}/{original_verification.id}")
    assert response.status_code == status.HTTP_200_OK, "Verification management is available"
    assert model.VerificationManagement.model_validate_json(response.content).expires_at == original_verification.expires_at
    response = client.get(f"request-object/{original_verification.authorization_request_id}")
    assert response.status_code == status.HTTP_200_OK, "Authorization object is available"

    # Wait until shortly before the ttl of the verification expires
    time.sleep(2)

    # Submit response data and refresh the ttl of the verification mgmt objetc
    response = _send_holder_vc_submission_and_token(
        client=client,
        authorization_request_id=original_verification.authorization_request_id,
        revoked=False,
        jwt_valid=True,
        credential=test_data.ELFA_SD_JWT,
    )
    assert response.status_code == status.HTTP_200_OK

    # Wait until the initial data should have definitely expired
    time.sleep(2)

    # Assert that ttl of verification and data have been increased but initial authorization_request has already expired
    response = client.get(f"{GENERIC_VERIFIER_PREFIX}/{original_verification.id}")
    assert response.status_code == status.HTTP_200_OK, "Verification management is available"
    assert original_verification.expires_at < model.VerificationManagement.model_validate_json(response.content).expires_at
    response_get_verification_management = client.get(f"{GENERIC_VERIFIER_PREFIX}/{original_verification.id}/response-data")
    assert response_get_verification_management.status_code == status.HTTP_200_OK
    response = client.get(f"request-object/{original_verification.authorization_request_id}")
    assert response.status_code == status.HTTP_404_NOT_FOUND, "Authorization object is available"


def test_jwt_utils_get_jwks(client):
    config = VerifierConfig()
    with pytest.raises(httpx.ConnectError):
        jwt_utils.get_jwks("should fail", config)
    failing_url = "https://thisshouldfail.example.com"
    with pytest.raises(httpx.ConnectError):
        # Test if the correct error is thrown
        jwt_utils.get_jwks(failing_url, config)
    try:
        # Test details on the exception
        jwt_utils.get_jwks(failing_url, config)
    except httpx.ConnectError as e:
        assert e.__notes__, "Should have additional notes"
        assert failing_url in ",".join(e.__notes__) or failing_url in repr(e), "Should find the failed url in notes or repr"
        http_error = err.UnavailableKeyError(additional_error_description=err.exception_to_additional_error_description("Test", e))
        assert http_error.status_code == 400, "Should have the status_code 400"
        assert failing_url in http_error.additional_error_description, "Should find the failing url in the additional description"
