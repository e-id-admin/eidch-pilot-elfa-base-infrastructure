# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import json
import uuid
import os
import logging

from common import jwt_utils
from common import parsing

DATA_DIR = "wallet_data"

_logger = logging.getLogger(__name__)


def load_credential_file(file_location: str):
    with open(file_location, 'r') as f:
        credential = json.load(f)
        try:
            if jwt_utils.is_sd_jwt(credential['credential']):
                return read_sd_jwt(credential['credential'])
            else:
                return read_jwt(credential['credential'])
        except Exception:
            _logger.error(f"{file_location=} {credential=}")
            raise


def load_raw_credential_file(file_location: str):
    with open(file_location, 'r') as f:
        return json.loads(f.read())


def get_credential_file_paths(user_name: str) -> list[str]:
    user_dir = os.path.join(DATA_DIR, user_name)
    paths = [os.path.join(user_dir, credential_file) for credential_file in os.listdir(user_dir)]
    return paths


def get_all_user_credentials_jwt(user_name: str) -> dict:
    creds = {path: load_raw_credential_file(path) for path in get_credential_file_paths(user_name)}
    return creds


def get_all_user_credentials_json(user_name: str) -> dict:
    creds = {path: load_credential_file(path) for path in get_credential_file_paths(user_name)}
    return creds


def save_credential(user_name: str, oid_credential) -> None:
    # TODO -> EID-1231: Save Credential with jti
    with open(os.path.join(DATA_DIR, user_name, str(uuid.uuid4())), 'w') as f:
        json.dump(oid_credential, f)


def delete_credential(user_name: str, credential_id: uuid.UUID) -> None:
    path = os.path.join(DATA_DIR, user_name, credential_id)
    os.remove(path)


def delete_all_credentials_from_user(user_name: str) -> None:
    user_credential_folder = os.path.join(DATA_DIR, user_name)
    if os.path.isdir(user_credential_folder):
        all_files = os.listdir(user_credential_folder)
        for file in all_files:
            delete_credential(user_name, file)


def read_jwt(jwt: str) -> dict:
    jwt_body = jwt_utils.split_jwt(jwt)[1]
    jwt_body_object = parsing.object_from_url_safe(jwt_body)
    assert isinstance(jwt_body_object, dict), f"JWT body was not a dict: {jwt_body_object}"
    return jwt_body_object


def read_sd_jwt(sd_jwt: str) -> list:
    jwt_str = jwt_utils.get_jwt_of_sdjwt(sd_jwt)
    secrets = jwt_utils.get_secrets_of_sdjwt(sd_jwt)
    jwt = read_jwt(jwt_str)
    return [jwt, list(map(parsing.object_from_url_safe, secrets))]


def get_first_user_credential_with_type(user_name: str, credential_types: list[str]) -> tuple[str, dict]:
    """
    Loads the raw and json version of the credential file accoding to the type provided. Takes the first matching one
    """
    credentials = get_all_user_credentials_json(user_name)
    searched_types = set(credential_types)
    logging.info(f"Searching - {credential_types}")
    for path, cred in credentials.items():
        c = cred[0] if type(cred) is list else cred
        credential_types = set(c['vc']['type'])
        if searched_types.intersection(credential_types):
            return load_raw_credential_file(path), cred
