# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
from httpx import Client

from common.key_configuration import KeyConfiguration

# API KEY TODO: Different API Keys for different servers
api_key = os.getenv("API_KEY", "tergum_dev_key")
wallet_key_conf = KeyConfiguration.load("cert/wallet")

JSON_REQUEST_HEADER_JSON = {
    'accept': 'application/json',
    'Content-Type': 'application/json',
}
API_KEY_HEADER = {'x-api-key': api_key}

# Servers
client_admin = Client(base_url=os.getenv("TEST_ADMIN", "https://localhost:1337"), verify=False, headers=API_KEY_HEADER)
client_issuer = Client(base_url=os.getenv("TEST_ISSUER", "https://localhost:8000"), verify=False, headers=API_KEY_HEADER)
client_verifier = Client(base_url=os.getenv("TEST_VERIFIER", "https://localhost:8001"), verify=False, headers=API_KEY_HEADER)
client_registry_base = Client(base_url=os.getenv("TEST_REGISTRY_BASE_ISSUER", "https://localhost:8010"), verify=False, headers=API_KEY_HEADER)
client_registry_revocation = Client(base_url=os.getenv("TEST_REGISTRY_REVOCATION_ISSUER", "https://localhost:8011"), verify=False, headers=API_KEY_HEADER)


root_path = os.path.dirname(os.path.realpath(__file__))
