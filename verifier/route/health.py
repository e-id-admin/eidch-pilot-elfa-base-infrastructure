# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""This file defines the custom health checks for the application."""

from fastapi import Response
from common.health import base

from verifier import config as conf
import verifier.cache.verifier_cache as cache


class HealthResponse(base.HealthResponse):
    """Response body model for health request operation."""

    configuration_verifier_has_minimum_config: base.HealthStatus = base.HealthStatus.unhealthy
    configuration_verifier_has_request_object_service: base.HealthStatus = base.HealthStatus.unhealthy
    configuration_verifier_has_verification_management_service: base.HealthStatus = base.HealthStatus.unhealthy
    configuration_verifier_has_presentation_definition_service: base.HealthStatus = base.HealthStatus.unhealthy
    configuration_verifier_has_authorization_response_data_service: base.HealthStatus = base.HealthStatus.unhealthy


class VerifierHealthAPIRouter(base.HealthAPIRouter):
    def __init__(self) -> None:
        super().__init__(debug_response_model=HealthResponse)

    def _build_debug_probe(
        self,
        result: HealthResponse,
        response: Response,
        config: conf.VerifierConfig,
    ) -> HealthResponse:
        result.configuration_verifier_has_minimum_config = bool(config.has_minimum_config())
        result.configuration_verifier_has_request_object_service = bool(cache.request_object_service)
        result.configuration_verifier_has_verification_management_service = bool(cache.verification_management_service)
        result.configuration_verifier_has_presentation_definition_service = bool(cache.presentation_definition_service)
        result.configuration_verifier_has_authorization_response_data_service = bool(cache.authorization_response_data_service)

        return super()._build_debug_probe(result, response, config)

    def get_debug_probe(
        self,
        response: Response,
        config: conf.inject,
    ):
        return self._build_debug_probe(
            result=HealthResponse(),
            response=response,
            config=config,
        )


router = VerifierHealthAPIRouter()
