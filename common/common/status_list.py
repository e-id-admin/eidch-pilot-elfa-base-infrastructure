# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Functions for Status List 2021
https://www.w3.org/TR/2023/WD-vc-status-list-20230427/
"""
from typing import Literal
import uuid
import bitarray

import gzip
import base64

from pydantic import BaseModel


def _from_bitarray_to_str(bit_data: bitarray.bitarray) -> str:
    """
    Converts a bitarray to StatusList2021 compatible b64 string
    """
    zipped = gzip.compress(bit_data.tobytes())
    encoded = base64.urlsafe_b64encode(zipped)
    return encoded.decode()


def _from_str_to_bitarray(encoded_data: str) -> bitarray.bitarray:
    """
    Converts the base64 encoded string to a bitarray
    """
    zipped = base64.urlsafe_b64decode(encoded_data)
    unzipped = gzip.decompress(zipped)
    a = bitarray.bitarray()
    a.frombytes(unzipped)
    return a


def from_string(base64_encoded: str) -> "StatusList2021":
    a = _from_str_to_bitarray(base64_encoded)
    return StatusList2021(a)


def create_empty(size: int) -> "StatusList2021":
    a = bitarray.bitarray("0" * size)
    return StatusList2021(a)


def create_full(size: int) -> "StatusList2021":
    a = bitarray.bitarray("1" * size)
    return StatusList2021(a)


class StatusList2021:
    def __init__(self, data: bitarray.bitarray):
        self.data = data

    def __str__(self) -> str:
        return self.pack()

    def set_bit(self, index: int, bit_value: bool = True):
        """
        Sets the bit at the index 0 to the given bit_value (True = 1, False = 0)
        """
        self.data[index] = int(bit_value)

    def pack(self) -> str:
        """
        Create the zipped & url-safe base64 encoded
        """
        return _from_bitarray_to_str(self.data)


class CredentialStatus(BaseModel):
    id: str
    """
    The value of the id property MUST be a URL which MAY be dereferenced.
    """
    type: str
    """
    Must express the credential status type, eg StatusList2021Entry
    """


class StatusList2021Entry(CredentialStatus):
    """
    https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry
    id is expected to be a URL that identifies the status information associated with the verifiable credential.
    id must not be the url for the status list.
    """

    type: Literal['StatusList2021Entry']
    statusPurpose: str
    statusListIndex: str
    """
    an arbitrary size integer greater than or equal to 0, expressed as a string
    identifies the bit position of the status of the verifiable credential
    """
    statusListCredential: str
    """
    MUST be a URL to a verifiable credential
    resulting verifiable credential MUST have type property that includes the StatusList2021Credential value
    """


class StatusListRegistryData(BaseModel):
    """
    Information for the Status List Registry
    """

    id: uuid.UUID
    issuer_id: uuid.UUID
    status_credential_jwt: str  # TODO -> EID-1256: Add pydantic(?) model for more unified unpacking
    nonce: uuid.UUID
