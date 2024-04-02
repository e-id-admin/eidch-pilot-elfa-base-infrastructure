# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging

from fastapi import Response
import httpx as req
from sqlalchemy.orm import Session

import common.db.postgres as db
from common import health

import registry_revocation.config as conf

_logger = logging.getLogger(__name__)


class RevocationRegistryReadinessHealthResponse(health.ReadinessHealthResponseWithDBInject):
    """Response body model for health request operation."""

    base_registry_connectivity: health.HealthStatus = health.HealthStatus.unhealthy


class RevocationRegistryHealthAPIRouter(health.HealthAPIRouterWithDBInject):
    def __init__(self) -> None:
        super().__init__(
            readiness_response_model=RevocationRegistryReadinessHealthResponse,
        )

    def _build_readiness_probe(
        self,
        result: RevocationRegistryReadinessHealthResponse,
        response: Response,
        config: conf.RevocationRegistryConfig,
        session: Session,
    ) -> RevocationRegistryReadinessHealthResponse:
        # Base Registry Connection
        uri = None
        try:
            uri = f"{config.registry_key_url}/health/readiness"
            key_reg_status = req.get(
                uri,
                verify=config.enable_ssl_verification,
            )
            result.base_registry_connectivity = key_reg_status.status_code == 200
        except Exception:
            _logger.exception(f"Health check for Base Registry ({uri=}) errors.")

        return super()._build_readiness_probe(result, response, config, session)

    def get_readiness_probe(
        self,
        response: Response,
        config: conf.inject,
        session: db.inject,
    ):
        return self._build_readiness_probe(
            RevocationRegistryReadinessHealthResponse(),
            response,
            config,
            session,
        )


router = RevocationRegistryHealthAPIRouter()
