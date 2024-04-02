# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import binascii

import pytest

from common import parsing


def test_uuid_parsing():
    """
    Tests parsing a uuid to a shorter base64 based string,
    containing the same bytes
    """
    id = uuid.uuid4()
    b64_id = parsing.uuid_to_url_safe(id)
    assert isinstance(b64_id, str)
    assert '=' in b64_id, "Should be a valid b64 with padding"
    short_b64_id = parsing.remove_padding(b64_id)
    assert '=' not in short_b64_id, "Remove padding should remove ="
    decoded = parsing.uuid_from_url_safe(b64_id)
    decoded_short = parsing.uuid_from_url_safe(short_b64_id)
    assert decoded == decoded_short, "Removing padding should have no effect"
    assert id == decoded, "Decoded and original uuid should be the same"

    try:
        # Test with an invalid base64 string
        parsing.uuid_from_url_safe("gugus")
        assert not True, "Should have an exception"
    except binascii.Error as e:
        assert e, "Thrown exception should be a binascii error"

    try:
        # Test with a valid base64 string, but invalid uuid
        parsing.uuid_from_url_safe("abc")
        assert not True, "Should have an exception"
    except ValueError as e:
        assert e, "Thrown exception should be a ValueError"


def test_object_parsing():
    test_object = {
        "str": "Hello World",
        "int": 5,
        "bool": True,
        "dict": {"inner": "data"},
    }
    b64 = parsing.object_to_url_safe(test_object)
    assert isinstance(b64, str)
    b64_short = parsing.remove_padding(b64)
    assert b64.startswith(b64_short)
    decoded = parsing.object_from_url_safe(b64)
    decoded_short = parsing.object_from_url_safe(b64_short)
    assert test_object == decoded_short
    assert test_object == decoded
    # Test some superfluous padding
    b64_overpadded = parsing.add_padding(b64)
    decoded_overpadded = parsing.object_from_url_safe(b64_overpadded)
    assert test_object == decoded_overpadded, "Unnecessary padding should not matter to the parser"
