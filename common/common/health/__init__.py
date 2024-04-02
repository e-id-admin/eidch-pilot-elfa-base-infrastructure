# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from .base import *  # noqa:F403,F401 Convenience imports

try:
    from .db_connection_check import *  # noqa:F403,F401 Convenience imports
except ModuleNotFoundError as e:
    # Guard for missing sqlalchemy module.
    DB_MODULES = ["sqlalchemy", "alembic"]
    if e.msg not in map(lambda module: f"No module named '{module}'", DB_MODULES):
        raise
