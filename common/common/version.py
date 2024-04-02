# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os

commit_hash = os.getenv("COMMIT_HASH", "no hash")
commit_time = os.getenv("COMMIT_TIMESTAMP", "no timestamp")
version = os.getenv("VERSION", "no version")


def get_version() -> str:
    return f"{version} ({commit_hash} {commit_time})"
