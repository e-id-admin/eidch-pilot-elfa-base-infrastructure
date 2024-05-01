# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""This file defines the custom health checks for the application."""
import logging

import httpx as req
from fastapi import Response

from common import health
import common.db.postgres as db
from sqlalchemy.orm import Session
import issuer.db.status_list as sl_db
import issuer.db.metadata as metadata_db
import issuer.config as conf
import common.key_configuration as key

_logger = logging.getLogger(__name__)


class DebugHealthResponse(health.HealthResponse):
    """Response body model for health request operation."""

    config_id_present: health.HealthStatus = health.HealthStatus.unhealthy
    config_metadata_present: health.HealthStatus = health.HealthStatus.unhealthy
    config_status_list_suspension_present: health.HealthStatus = health.HealthStatus.unhealthy
    config_status_list_revocation_present: health.HealthStatus = health.HealthStatus.unhealthy
    status_list_connectivity: health.HealthStatus = health.HealthStatus.unhealthy


class ReadinessHealthResponse(health.ReadinessHealthResponseWithDBInject):
    """Response body model for health request operation."""

    base_registry_connectivity: health.HealthStatus = health.HealthStatus.unhealthy


class LivelinessHealthResponse(health.base.HealthResponse):
    """Response body model for health request operation."""

    public_key_is_available: health.HealthStatus = health.HealthStatus.unhealthy


class IssuerHealthAPIRouter(health.HealthAPIRouterWithDBInject):
    def __init__(self) -> None:
        super().__init__(
            readiness_response_model=ReadinessHealthResponse,
            liveness_response_model=LivelinessHealthResponse,
            debug_response_model=DebugHealthResponse,
        )

    def _build_readiness_probe(
        self,
        result: ReadinessHealthResponse,
        response: Response,
        config: conf.IssuerConfig,
        session: Session,
    ) -> ReadinessHealthResponse:
        # Base Registry Connection
        uri = None
        try:
            uri = config.get_key_registry_uri()
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
            ReadinessHealthResponse(),
            response,
            config,
            session,
        )

    def _build_liveness_probe(
        self,
        result: LivelinessHealthResponse,
        response: Response,
        config: conf.IssuerConfig,
        key_conf: key.KeyConfiguration,
    ) -> LivelinessHealthResponse:
        """Provides information regarding issues which could be
        resolved through a application instance restart."""

        # Check if public key is available (especially needed in HSM connection loss scenario)
        try:
            key_conf.get_pk()
            result.public_key_is_available = health.HealthStatus.healthy
        except Exception:
            _logger.exception("Cannot get issuing public key.")

        return super()._build_liveness_probe(result, response, config)

    def get_liveness_probe(
        self,
        response: Response,
        config: conf.inject,
        key_conf: key.inject,
    ) -> LivelinessHealthResponse:
        """Determines whether the application instance needs to be restarted."""
        return self._build_liveness_probe(
            result=LivelinessHealthResponse(),
            response=response,
            config=config,
            key_conf=key_conf,
        )

    def _build_debug_probe(
        self,
        result: DebugHealthResponse,
        response: Response,
        config: conf.IssuerConfig,
        session: Session,
    ) -> DebugHealthResponse:
        # Issuer configuration
        result.config_id_present = bool(config.issuer_id)
        result.config_metadata_present = metadata_db.get_metadata(session) is not None

        result.status_list_connectivity = health.HealthStatus.healthy
        for purpose, status_list_id in config.status_list_map.items():
            if purpose == "revocation":
                result.config_status_list_revocation_present = health.HealthStatus.healthy
            elif purpose == "suspension":
                result.config_status_list_suspension_present = health.HealthStatus.healthy
            list_uri = config.get_status_list_uri(purpose)
            try:
                req.get(
                    list_uri,
                    verify=config.enable_ssl_verification,
                ).raise_for_status()

            except Exception:
                _logger.exception(
                    f"""Error in health checking status list {status_list_id}.
                    Cannot receive status list at {list_uri}.""",
                )
                result.status_list_connectivity = health.HealthStatus.unhealthy

            try:
                sl_db.get_status_list(status_list_id=status_list_id, session=session)
            except Exception:
                _logger.exception(
                    f"""Error in health checking status list {status_list_id}.
                    Issue in db resolving status list at {list_uri}.""",
                )
                result.status_list_connectivity = health.HealthStatus.unhealthy
        return super()._build_debug_probe(result, response, config)

    def get_debug_probe(
        self,
        response: Response,
        config: conf.inject,
        session: db.inject,
    ):
        return self._build_debug_probe(
            DebugHealthResponse(),
            response,
            config,
            session,
        )


router = IssuerHealthAPIRouter()
