# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
from fastapi import status
from httpx import Client

api_key = os.getenv("API_KEY", "tergum_dev_key")
API_KEY_HEADER = {'x-api-key': api_key}
client_wallet = Client(base_url=os.getenv("TEST_WALLET", "https://localhost:443"), verify=False, headers=API_KEY_HEADER)
UNIT_TEST_USER = "unit_test_user"


def delete_all_test_credentials():
    """Deletes test user data using the wallet"""
    client_wallet.delete(f"/data/{UNIT_TEST_USER}")


def wallet_verify_credential(request_object_url: str) -> tuple[int, str]:
    response = client_wallet.post(f"/data/{UNIT_TEST_USER}/verification_status", data={"auth_request": request_object_url})
    return response.status_code, response.text


def wallet_redeem_offer_failure(deeplink: str) -> dict:
    # Ensure unit test user exists
    response = client_wallet.post("/", data={"user_name": UNIT_TEST_USER})
    assert response.status_code == status.HTTP_200_OK, response.text
    response = client_wallet.post(f"/data/{UNIT_TEST_USER}", data={"deeplink": deeplink})
    assert response.status_code == status.HTTP_500_INTERNAL_SERVER_ERROR, response.text
    return response.json()


def wallet_redeem_offer(deeplink: str) -> tuple[tuple[dict, list[list]], str]:
    """Redeem offer with the web wallet service and return the redeemed credential
    Return ((credential_json, credential_secrets), credential_jwt) of the credential
    """
    # Ensure unit test user exists
    response = client_wallet.post("/", data={"user_name": UNIT_TEST_USER})
    assert response.status_code == status.HTTP_200_OK
    # Fetch existing data
    response = client_wallet.get(f"/data/{UNIT_TEST_USER}/json")
    assert response.status_code == status.HTTP_200_OK
    # Data we get back is a list of dicts (jwt) & lists (sd-jwt)
    old_data: set = {cred['jti'] if isinstance(cred, dict) else cred[0]['jti'] for cred in response.json()}

    # Fetch existing raw data
    response = client_wallet.get(f"/data/{UNIT_TEST_USER}/jwt")
    assert response.status_code == status.HTTP_200_OK
    raw_old_data = [cred["credential"] for cred in response.json()]

    response = client_wallet.post(f"/data/{UNIT_TEST_USER}", data={"deeplink": deeplink})
    assert response.status_code == status.HTTP_200_OK, f"{response.text}"

    response = client_wallet.get(f"/data/{UNIT_TEST_USER}/json")
    new_data: dict = {cred['jti'] if isinstance(cred, dict) else cred[0]['jti']: cred for cred in response.json()}

    response = client_wallet.get(f"/data/{UNIT_TEST_USER}/jwt")
    assert response.status_code == status.HTTP_200_OK
    raw_new_data = [cred["credential"] for cred in response.json()]

    assert len(new_data) > len(old_data)
    new_credential = new_data[set(new_data.keys()).difference(old_data).pop()]
    new_credential_raw = set(raw_new_data).difference(raw_old_data).pop()
    return new_credential, new_credential_raw
