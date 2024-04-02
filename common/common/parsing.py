# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import base64
import json
import re


def object_to_url_safe(data: dict | str | list) -> str:
    """Convert the object to an url safe base64 encoded JSON string."""
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


def object_from_url_safe(data: str) -> dict | str | list:
    """Load an JSON object from an url safe base64 encoded string. Adds padding as needed."""
    return json.loads(base64.urlsafe_b64decode(add_padding(data)))


def uuid_to_url_safe(id: uuid.UUID) -> str:
    """Encode the UUID bytes to a url_safe b64 encoded string"""
    return base64.urlsafe_b64encode(id.bytes).decode()


def uuid_from_url_safe(data: str) -> uuid.UUID:
    """
    Create a UUID from b64 encoded bytes. Adds padding as needed.
    Throws ValueError if data is not a valid uuid or b64
    """
    uuid_bytes = base64.urlsafe_b64decode(add_padding(data))
    return uuid.UUID(bytes=uuid_bytes)


def remove_padding(base64_encoded: str) -> str:
    """Remove padding form b64 encoded string"""
    return base64_encoded.rstrip('=')


def add_padding(base64_encoded: str) -> str:
    """Add padding (=) for b64 encoded string, so it can be decoded"""
    return f'{base64_encoded}==='


def interpret_as_bool(boolify: str) -> bool:
    """
    Converts an inpput to an boolean according to commonly used patterns.
    """
    if isinstance(boolify, bool):
        return boolify
    if isinstance(boolify, int):
        return boolify > 0
    elif isinstance(boolify, str):
        return re.match(r"^(y|yes|1|true)$", boolify, re.IGNORECASE | re.MULTILINE) is not None
    raise Exception(f"Can't boolify a {boolify}.")
