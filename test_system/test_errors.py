# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Testing Various errors on system level
"""

import datetime
import json
import time

import pytest

import common.credential_offer as co
import common.verifiable_credential as vc
import common.test_helpers.wallet_helper as wh
import issuer.test.hardcoded_creds as dummy

import verifier.models

import test_setup
from test_setup import test_setup_teardown  # noqa: F401 used by pytest

from test_system.test_environment import (
    client_issuer,
    client_verifier,
    JSON_REQUEST_HEADER_JSON,
)


def _create_test_offer_request() -> co.CredentialOfferData:
    """Create a valid VC offer"""
    valid_from = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    valid_until = datetime.datetime.utcnow() + datetime.timedelta(days=1)
    return co.CredentialOfferData(
        metadata_credential_supported_id="sd_tergum_dummy_jwt",
        credential_subject_data=dummy.get_random_degree_credential_data(),
        validity_seconds=604800,
        credential_valid_from=valid_from.isoformat(),
        credential_valid_until=valid_until.isoformat(),
    )


def _wallet_verification_run_success():
    """Create a verification request and let the wallet run at it, checking success"""
    # Get a Verification Request
    verification_management = test_setup._create_verficiation_verification_management()

    # Do verification with expired VC
    wallet_status_code, response_body = wh.wallet_verify_credential(verification_management.authorization_request_object_uri)
    assert wallet_status_code == 200, json.loads(json.loads(response_body)['response_body'])

    # Status should be also available at verifier
    test_setup._check_verification_process_status(
        verification_management.id,
        verifier.models.VerificationStatus.SUCCESS,
    )


def _wallet_verification_run_failure(expected_error_code: str):
    """Create a verification request and let the wallet run at it, checking for failure in state and error codes"""
    # Get a Verification Request
    verification_management = test_setup._create_verficiation_verification_management()

    # Do verification with expired VC
    wallet_status_code, response_body = wh.wallet_verify_credential(verification_management.authorization_request_object_uri)
    assert wallet_status_code == 400
    error_body = json.loads(json.loads(response_body)['response_body'])
    assert error_body['error_code'] == expected_error_code

    # Status should be also available at verifier
    test_setup._check_verification_process_status(
        verification_management.id,
        verifier.models.VerificationStatus.FAILED,
    )

    r = client_verifier.get(f"/oid4vp/verification/{verification_management.id}/response-data")
    assert r.status_code == 200, r.text
    response_data = verifier.models.AuthorizationResponseData.model_validate_json(r.text)
    assert response_data.error_code == expected_error_code


def test_expired_offer():
    """System test when the offer is expired"""
    offer = _create_test_offer_request()
    offer.offer_validity_seconds = 0
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json=offer.model_dump(),
        headers=JSON_REQUEST_HEADER_JSON,
    )
    assert r.status_code == 200, r.text
    offer_data = r.json()
    offer_deeplink = offer_data['offer_deeplink']
    # Wait 1 sec to ensure that it will be indeed be expired
    time.sleep(1)
    response = wh.wallet_redeem_offer_failure(offer_deeplink)
    assert 'detail' in response and "Offer did expire" in response['detail'], response


def test_used_offer():
    """The Offer has already been used before"""
    offer = _create_test_offer_request()
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json=offer.model_dump(),
        headers=JSON_REQUEST_HEADER_JSON,
    )

    assert r.status_code == 200, r.text
    offer_data = r.json()
    offer_deeplink = offer_data['offer_deeplink']
    offer_management_id = offer_data['management_id']

    assert test_setup._call_generic_credential_status(offer_management_id) == 'Offered'

    _ = wh.wallet_redeem_offer(offer_deeplink)  # We dont care about the vc as long as successfull

    assert test_setup._call_generic_credential_status(offer_management_id) == 'Issued'

    response = wh.wallet_redeem_offer_failure(offer_deeplink)
    assert 'detail' in response, response
    assert test_setup._call_generic_credential_status(offer_management_id) == 'Issued'


def test_expired_vc():
    """
    Create a valid VC offer. The validUntil is though in the past.
    Attempt to verify with the invalid VC
    """
    offer = _create_test_offer_request()
    # Get an expired credential
    offer.credential_valid_from = datetime.datetime.utcnow() - datetime.timedelta(days=2)
    offer.credential_valid_until = datetime.datetime.utcnow() - datetime.timedelta(days=1)
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json=offer.model_dump(),
        headers=JSON_REQUEST_HEADER_JSON,
    )

    assert r.status_code == 200, r.text
    offer_deeplink = r.json()['offer_deeplink']
    (credential, disclosures), sd_jwt = wh.wallet_redeem_offer(offer_deeplink)

    credential = vc.JsonWebTokenBodyVCData.model_validate(credential)

    assert not credential.is_date_valid(), "EXP of jwt should reflect expiration"
    assert not credential.vc.is_date_valid(), "VC Validity should be expired."

    _wallet_verification_run_failure(expected_error_code="jwt_expired")


def test_vc_states():
    """
    Get a valid credential
    suspend the credential and try to verify with it.
    unsuspend the credential (verification should now work)
    revoke the credential
    """
    offer = _create_test_offer_request()
    r = client_issuer.post(
        "oid4vc/credential/offer",
        json=offer.model_dump(),
        headers=JSON_REQUEST_HEADER_JSON,
    )

    assert r.status_code == 200, r.text
    offer_data = r.json()
    offer_deeplink = offer_data['offer_deeplink']
    offer_management_id = offer_data['management_id']
    (credential, disclosures), sd_jwt = wh.wallet_redeem_offer(offer_deeplink)

    credential = vc.JsonWebTokenBodyVCData.model_validate(credential)

    _wallet_verification_run_success()

    # Suspend
    test_setup._call_generic_change_credential_status(offer_management_id, 'suspension', True)
    _wallet_verification_run_failure(expected_error_code="credential_suspended")

    # UnSuspend
    test_setup._call_generic_change_credential_status(offer_management_id, 'suspension', False)
    _wallet_verification_run_success()

    # Revoke
    test_setup._call_generic_change_credential_status(offer_management_id, 'revocation', True)
    _wallet_verification_run_failure(expected_error_code="credential_revoked")


@pytest.fixture(autouse=True)
def error_test_setup_teardown(test_setup_teardown):  # noqa: F811 used by pytest
    # Ensure status lists are correct
    test_setup.client_issuer.patch("/admin/status-list")
    yield
