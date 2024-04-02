# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
from typing import Type
from fastapi import FastAPI, Request, HTTPException
from fastapi.exception_handlers import http_exception_handler


import contextlib

from common.logging.setup import configure_logging, get_log_id
from common.version import get_version
from common import config as conf

_logger = logging.getLogger(__name__)


class ExtendedFastAPI(FastAPI):
    """
    Wrapper for the FastAPI class which extends it with the commonly used patterns for this project.
    """

    @staticmethod
    @contextlib.contextmanager
    def _logging_lifespan(app: "ExtendedFastAPI") -> contextlib.AbstractContextManager:
        configure_logging(app.config_instance)
        yield

    @staticmethod
    @contextlib.asynccontextmanager
    async def lifespan(app: "ExtendedFastAPI") -> contextlib.AbstractAsyncContextManager:
        with contextlib.ExitStack() as stack:
            # Enter the context of all lifespans
            [stack.enter_context(lifespan_function) for lifespan_function in app.lifespan_functions]
            yield
            # Close all lifespans
            stack.pop_all().close()

    def __init__(
        self,
        config: Type[conf.Config],
        lifespan_functions: list[contextlib.AbstractContextManager] = [],
        *args,
        **kwargs,
    ) -> None:
        """
        Wrapper for the FastAPI class which extends it with the following, optional, features.

        Those are enabled by feature flags in the config or overwritten at construction.
        Features:
         - Enablement of documentation endpoints
         - App name configuration as FastAPI app title
         - Automatic version detection
         - Configuration of logging output
         - Secure API with apikey
         - Enablement of CORs
        For detailed information regarding optional configuration please refer to `FastAPI`
        https://fastapi.tiangolo.com/reference/fastapi/
        """
        self.config_instance = config()

        # As most configuration needs to be provided through the constructor
        # call to FastAPI we manipulate the kwargs to create optional
        # enablement of features.
        if not self.config_instance.enable_documentation_endpoints:
            _logger.info("Deactivate documentation endpoints.")
            kwargs["docs_url"] = None
            kwargs["redoc_url"] = None
            kwargs["openapi_url"] = None

        if "title" not in kwargs:
            kwargs['title'] = self.config_instance.app_name

        if "version" not in kwargs:
            kwargs['version'] = get_version()

        self.lifespan_functions = [ExtendedFastAPI._logging_lifespan(self)]
        self.lifespan_functions.extend(lifespan_functions)

        if "lifespan" not in kwargs:
            kwargs['lifespan'] = ExtendedFastAPI.lifespan

        super().__init__(
            *args,
            **kwargs,
        )
        if self.config_instance.enable_cors:
            _logger.info("Activate CORs support.")
            from fastapi.middleware.cors import CORSMiddleware

            allowed_origins = [self.config_instance.external_url if self.config_instance.external_url else '*']
            if self.config_instance.additional_allowed_origins:
                allowed_origins += self.config_instance.additional_allowed_origins.split(',')
            self.add_middleware(
                CORSMiddleware,
                allow_origins=allowed_origins,
                allow_credentials=True,
                allow_methods=["*"],
                allow_headers=["*"],
            )
        self.add_exception_handler(Exception, self.unhandled_exception_handler)

    async def unhandled_exception_handler(self, request: Request, exc: Exception):
        if not isinstance(exc, HTTPException):
            _logger.error("Unhandled exception detected.")
            # logging of the original error is done by fastapi/starlette
            exc = HTTPException(
                500,
                f'Could not process the request. Please contact support with request id {get_log_id()}',
            )

        return await http_exception_handler(request, exc)
