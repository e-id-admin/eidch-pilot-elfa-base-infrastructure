# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Wrapper for httpx functions to add additional context"""

from common import config as conf


import httpx
from httpx import ConnectError


def get(url: str, config: conf.Config) -> httpx.Response:
    """Wrapper for httpx.get call, on error adds additional information to exception
    By default httpx.Connection error only provides '[Errno -2] Name or service not known'
    Throws httpx.ConnectError with URL & ssl verification status on failure to
        get connection to the service
    """
    try:
        return httpx.get(url, verify=config.enable_ssl_verification)
    except ConnectError as e:
        error_msg = f"Failed to GET verification data {url=} with {config=}"
        e.add_note(error_msg)
        raise
