# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""Provide functionality to check the sql database connectivity.

Only available if the sqlalchemy module is present."""

import logging

from sqlalchemy import text

from fastapi import Response

import common.config as conf
import common.db.postgres as db
from common.health import base

_logger = logging.getLogger(__name__)


def check_health_of_db(session_to_check: db.Session) -> base.HealthStatus:
    """Checks weather the session is active or not.

    Args:
        session_to_check (db.Session): session to check

    Returns:
        bool: True if health is ok
    """

    result = False
    try:
        session_to_check.execute(text('SELECT 1'))
        result = session_to_check.is_active
    except Exception:
        _logger.exception("Error in health check db probe.")
    return base.HealthStatus.healthy if result else base.HealthStatus.unhealthy


class ReadinessHealthResponseWithDBInject(base.HealthResponse):
    """Response body model for health request operation."""

    db_connectivity: base.HealthStatus = base.HealthStatus.unhealthy


class HealthAPIRouterWithDBInject(base.HealthAPIRouter):
    """Create a api router for common health endpoints
    `/health/`, `/health/liveness` and `/health/readiness`.

    This router includes checks for the default database used in the `commons` module.
    Please see the documentation at `HealthAPIRouter` for further instructions how to
    use and extend this class.
    """

    def __init__(
        self,
        readiness_response_model: type(ReadinessHealthResponseWithDBInject) = ReadinessHealthResponseWithDBInject,
        liveness_response_model: type(base.HealthResponse) = base.HealthResponse,
        debug_response_model: type(base.HealthResponse) = base.HealthResponse,
        *args,
        **kwargs
    ) -> None:
        super().__init__(
            readiness_response_model,
            liveness_response_model,
            debug_response_model,
            *args,
            **kwargs,
        )

    def _build_readiness_probe(
        self,
        result: ReadinessHealthResponseWithDBInject,
        response: Response,
        config: conf.Config,
        session: db.Session,
    ) -> ReadinessHealthResponseWithDBInject:
        """Provides information regarding issues which prevent the application to function properly.
        Therefore if any probe fails the system should not receive any data."""

        result.db_connectivity = check_health_of_db(session)
        return super()._build_readiness_probe(result, response, config)

    def get_readiness_probe(
        self,
        response: Response,
        config: conf.inject,
        session: db.inject,
    ) -> ReadinessHealthResponseWithDBInject:
        """Determines whether the application instance is ready to accept requests.

        Also checks external systems if they are available
        """

        return self._build_readiness_probe(
            ReadinessHealthResponseWithDBInject(),
            response,
            config,
            session,
        )
