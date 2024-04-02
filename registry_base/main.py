# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import common.config
import fastapi
import common.db.postgres as db
import registry_base.registry as app_source


def startup() -> fastapi.FastAPI:

    config = common.config.DBConfig()
    db.alembic_upgrade(config.ALEMBIC_CONFIG_FILE)
    return app_source.app


app = startup()
