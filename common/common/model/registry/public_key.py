# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
from pydantic import BaseModel

from common.model.ietf import JSONWebKeySet

class PublicKeyRegistryData(BaseModel):
    public_key_set:JSONWebKeySet
    id: uuid.UUID
    nonce: uuid.UUID