# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Configuration definition and collector of default values."""

import os
from typing import Annotated

from fastapi import Depends

import common.config as conf


class RegistryBaseConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Public Key Registry")

        self.use_https = os.getenv("USE_HTTPS", True)
        '''Configures if base registry should use https for all links (should be only False on local environments)'''


inject = Annotated[RegistryBaseConfig, Depends(RegistryBaseConfig)]
