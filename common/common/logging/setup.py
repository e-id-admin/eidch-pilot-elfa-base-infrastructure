# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import logging
import sys

from asgi_correlation_id import CorrelationIdFilter, correlation_id

from common.config import Config
from common.logging import splunk

_correlation_id_length = 16


def get_log_id() -> str:
    return correlation_id.get()[:_correlation_id_length]


def configure_logging(config: Config) -> None:
    console_handler = logging.StreamHandler(stream=sys.stdout)

    _cid_filter = CorrelationIdFilter(uuid_length=_correlation_id_length)
    # Add correlation id to handlers
    console_handler.addFilter(_cid_filter)

    # setup splunk if necessary
    if config.enable_splunk_log:
        _formatter = splunk.SplunkFormatter(defaults={"app_name": config.app_name})
        console_handler.setFormatter(_formatter)

    logging.basicConfig(handlers=[console_handler], level=config.log_level)

    # Configure all loggers to use the console logger
    for logger in logging.root.manager.loggerDict.values():
        if isinstance(logger, logging.Logger):
            if console_handler not in logger.handlers:
                logger.handlers = [console_handler]
                logger.propagate = False
