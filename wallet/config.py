# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
from typing import Annotated

from fastapi import Depends

import common.config as conf


class WalletConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Wallet")


inject = Annotated[WalletConfig, Depends(WalletConfig)]
