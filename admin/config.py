# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Configuration definition and collector of default values."""
import os
from typing import Annotated

from fastapi import Depends

import common.config as conf


class AdminConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Admin Service")


inject = Annotated[AdminConfig, Depends(AdminConfig)]
