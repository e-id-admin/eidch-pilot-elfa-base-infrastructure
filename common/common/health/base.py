# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from enum import Enum

from pydantic import BaseModel

from fastapi import APIRouter, status, Response

import common.config as conf


class HealthStatus(Enum):
    """Indicator of system health."""

    healthy = "HEALTHY"
    unhealthy = "UNHEALTHY"


class HealthResponse(BaseModel):
    """Response body model for health request operation.

    May only contain `HealthStatus` fields. Those can be set with boolean values,
    those get converted before the model is returned to the client."""

    http_server_connectivity: HealthStatus = HealthStatus.unhealthy
    """Superfluous information as it can only be returned from the http server if healthy,

    but it may illustrate how to use the `HealthChecks` base model
    """

    def convert_from_bool(self) -> None:
        '''Converts every boolean field into its `HealthStatus` representation.

        This is a health module internal convenience function,
        to not always use the full ternary operator.'''
        for k, v in iter(self):
            if isinstance(v, bool):
                setattr(self, k, HealthStatus.healthy if v else HealthStatus.unhealthy)

    def is_healthy(self) -> bool:
        """Summarizes all checks performed into the status field."""
        return all([v == HealthStatus.healthy for _, v in iter(self)])


class HealthAPIRouter(APIRouter):
    """Create a api router for common health endpoints
    `/health/`, `/health/liveness` and `/health/readiness`.

    You may extend this router with application specific checks. To do so
    create your own child class of `HealthResponse`, `HealthChecks` and `HealthAPIRouter`.
    Extend your `HealthChecks` according to your needs and overwrite the _build* and get_*
    methods.

    Also call the constructor of `HealthAPIRouter` with your class names
    for the respective endpoints.
    """

    def __init__(
        self,
        readiness_response_model: type(HealthResponse) = HealthResponse,
        liveness_response_model: type(HealthResponse) = HealthResponse,
        debug_response_model: type(HealthResponse) = HealthResponse,
        *args,
        **kwargs,
    ) -> None:
        """Create a api router for common health endpoints
        `/health/`, `/health/liveness` and `/health/readiness`.

        You may overwrite the response models to use for the endpoints as necessary.

        For further keywords please see the fastapi documentation of `APIRouter`

        Args:
            readiness_response_model (type, optional): Response model of `/health/readiness`. Defaults to HealthResponse.
            liveness_response_model (type, optional): Response model of `/health/liveness`. Defaults to HealthResponse.
            debug_response_model (type, optional): Response model of `/health`. Defaults to HealthResponse.
        """
        super().__init__(prefix="/health", tags=["Health"], *args, **kwargs)
        self.add_api_route(
            "/debug",
            endpoint=self.get_debug_probe,
            description="Provides information regarding debug and config states.",
            responses={
                status.HTTP_200_OK: {"model": debug_response_model},
                status.HTTP_503_SERVICE_UNAVAILABLE: {"model": debug_response_model},
            },
        )
        self.add_api_route(
            "/liveness",
            endpoint=self.get_liveness_probe,
            description="Determines whether the application instance needs to be restarted.",
            responses={
                status.HTTP_200_OK: {"model": liveness_response_model},
                status.HTTP_503_SERVICE_UNAVAILABLE: {"model": liveness_response_model},
            },
        )
        self.add_api_route(
            "/readiness",
            endpoint=self.get_readiness_probe,
            description="Determines whether the application instance is ready to accept requests.",
            responses={
                status.HTTP_200_OK: {"model": readiness_response_model},
                status.HTTP_503_SERVICE_UNAVAILABLE: {"model": readiness_response_model},
            },
        )

    def __resolve_probe(self, result: HealthResponse, response: Response) -> HealthResponse:
        """Evaluates the `result` and interprets it according to the checks performed.

        Args:
            result (HealthResponse): The daisy chained response object holding the probe results.
            response (Response): The response object where to set the resulting http code.

        Returns:
            HealthResponse: The daisy chained response object holding the probe results.
        """
        result.http_server_connectivity = HealthStatus.healthy
        result.convert_from_bool()
        if result.is_healthy():
            response.status_code = status.HTTP_200_OK
        else:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return result

    def _build_debug_probe(
        self,
        result: HealthResponse,
        response: Response,
        config: conf.Config,
    ) -> HealthResponse:
        """Provides information regarding debug and config states."""
        return self.__resolve_probe(result, response)

    def get_debug_probe(self, response: Response, config: conf.inject) -> HealthResponse:
        """Provides information regarding debug and config states."""
        return self._build_debug_probe(
            result=HealthResponse(),
            response=response,
            config=config,
        )

    def _build_liveness_probe(
        self,
        result: HealthResponse,
        response: Response,
        config: conf.Config,
    ) -> HealthResponse:
        """Provides information regarding issues which could be
        resolved through a application instance restart."""

        return self.__resolve_probe(result, response)

    def get_liveness_probe(self, response: Response, config: conf.inject) -> HealthResponse:
        """Determines whether the application instance needs to be restarted."""
        return self._build_liveness_probe(
            result=HealthResponse(),
            response=response,
            config=config,
        )

    def _build_readiness_probe(
        self,
        result: HealthResponse,
        response: Response,
        config: conf.Config,
    ) -> HealthResponse:
        """Provides information regarding issues which prevent the application to function properly.
        Therefore if any probe fails the system should not receive any data."""

        return self.__resolve_probe(result, response)

    def get_readiness_probe(self, response: Response, config: conf.inject) -> HealthResponse:
        """Determines whether the application instance is ready to accept requests.

        Also checks external systems if they are available
        """
        return self._build_readiness_probe(
            result=HealthResponse(),
            response=response,
            config=config,
        )
