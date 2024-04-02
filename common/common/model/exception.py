# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from pydantic import BaseModel

class HTTPError(BaseModel):
    """
    General HTTPException raised
    """
    detail: str