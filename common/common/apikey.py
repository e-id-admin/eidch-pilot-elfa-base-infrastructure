# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

from common import config


def require_api_key(conf: config.inject, api_key: str = Security(APIKeyHeader(name="x-api-key", auto_error=False))) -> None:
    if api_key != conf.api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing API Key")
