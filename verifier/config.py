# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
import re
import common.config as conf
from typing import Annotated
from fastapi import Depends

from common.parsing import interpret_as_bool


class VerifierConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Verifier Agent")
        self.verifier_url = os.getenv("EXTERNAL_URL", "https://localhost:8001")
        self.verification_ttl = os.getenv("VERIFICATION_TTL", 86400)
        """
        Data lives 1 day (60*60*24 = 86400 secs) in the storage
        """

        self.filter_allowed_issuers_regex: re.Pattern = re.compile(
            os.getenv("FILTER_ALLOWED_ISSUERS_REGEX", ".*"),
        )
        """
        Regex to match against the VCs issuer during the verification check.
        """

    def has_minimum_config(self) -> bool:
        return all([self.verifier_url, self.api_key])


inject = Annotated[VerifierConfig, Depends(VerifierConfig)]
