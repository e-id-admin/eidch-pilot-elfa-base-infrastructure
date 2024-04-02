# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging

from fastapi import Response

import common.db.postgres as db
from common import health

import admin.config as conf
import admin.db as admin_db

_logger = logging.getLogger(__name__)


class HealthResponse(health.HealthResponse):
    """Response body model for health request operation."""

    base_db_connectivity: health.HealthStatus = health.HealthStatus.unhealthy
    revocation_db_connectivity: health.HealthStatus = health.HealthStatus.unhealthy


class AdminHealthAPIRouter(health.HealthAPIRouter):
    def __init__(self, response_model: type(HealthResponse) = HealthResponse, *args, **kwargs) -> None:
        super().__init__(response_model, *args, **kwargs)

    def _build_readiness_probe(
        self,
        result: HealthResponse,
        response: Response,
        config: conf.AdminConfig,
        base_db_session: db.Session,
        revocation_db_session: db.Session,
    ) -> HealthResponse:
        result.base_db_connectivity = health.check_health_of_db(base_db_session)
        result.revocation_db_connectivity = health.check_health_of_db(revocation_db_session)
        return super()._build_readiness_probe(result, response, config)

    def get_readiness_probe(
        self,
        response: Response,
        config: conf.inject,
        base_db_session: admin_db.base_db_inject,
        revocation_db_session: admin_db.revocation_db_inject,
    ) -> HealthResponse:
        return self._build_readiness_probe(
            HealthResponse(),
            response,
            config,
            base_db_session,
            revocation_db_session,
        )
