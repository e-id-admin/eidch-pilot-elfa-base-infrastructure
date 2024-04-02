# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import json
from jwcrypto import jwk
from common.model import ietf


def test_serialization_of_jwk():
    k1 = jwk.JWK.generate(kty='EC', size=521)
    k2 = jwk.JWK.generate(kty='EC', size=521)
    k3 = jwk.JWK.generate(kty='EC', size=521)

    key1 = ietf.JSONWebKey.model_validate(k1.export_public(as_dict=True))
    # Same Key but different order
    key2 = ietf.JSONWebKey(**json.loads(k1.export_public(k1.export_public())))
    key3 = ietf.JSONWebKey.model_validate_json(k2.export_public())
    key4 = ietf.JSONWebKey.model_validate_json(k3.export_public())
    assert key1 == key2
    assert key1 != key3
    assert key1 != key4
    assert key2 != key3
