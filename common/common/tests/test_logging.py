# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import re
import json
import logging

import pytest

from common.logging import setup as log_setup, operations, splunk

from common import config as conf


def setup():
    # minimal setup to start logging
    app_config = conf.Config()
    app_config.app_name = "Logging Test"
    app_config.enable_splunk_log = True
    app_config.log_level = "INFO"
    access_logger = logging.getLogger("uvicorn")
    access_logger.addHandler(None)

    log_setup.configure_logging(app_config)


@pytest.fixture()
def formatted_caplog(caplog):
    formatter = splunk.SplunkFormatter(
        defaults={
            "app_name": "test_app",
            "correlation_id": "test",
        }
    )
    caplog.handler.setFormatter(formatter)
    return caplog


def _test_formatted_log(data_str: str, expected_message: str | bool, expected_level: str) -> None:
    data: dict[str, object] = json.loads(data_str)
    keys = data.keys()
    assert "message" in keys
    if expected_message is not False:
        assert data["message"] == expected_message
    assert "level" in keys
    assert data["level"] == expected_level
    assert "hash" in keys
    assert data["hash"] == "test"  # set in setup()
    assert "@timestamp" in data.keys()
    # Expected format: 2024-02-07T14:38:19.565+01:00
    assert re.match(
        r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,6})?[+-][0-9]{2}:[0-9]{2}",
        data["@timestamp"],
    )
    assert "app" in keys
    assert data["app"] == "test_app"


def _test_formatted_log_for_use_case(data_str: str, expected_operation: str, expected_step: str, expected_status: str) -> None:

    data: dict[str, object] = json.loads(data_str)
    keys = data.keys()

    assert "operation" in keys
    assert data["operation"] == expected_operation
    assert "step" in keys
    assert data["step"] == expected_step
    assert "status" in keys
    assert data["status"] == expected_status


def test_formatter(formatted_caplog):

    logger = logging.getLogger(f"{__name__}_test_formatter")

    with formatted_caplog.at_level("DEBUG"):
        formatted_caplog.clear()
        message = "ERROR message for testing"
        logger.error(message)
        assert len(formatted_caplog.records) == 1
        _test_formatted_log(formatted_caplog.text, message, "ERROR")

        formatted_caplog.clear()
        message = "WARN message for testing"
        logger.warn(message)
        assert len(formatted_caplog.records) == 1
        _test_formatted_log(formatted_caplog.text, message, "WARNING")

        formatted_caplog.clear()
        message = "INFO message for testing"
        logger.info(message)
        assert len(formatted_caplog.records) == 1
        _test_formatted_log(formatted_caplog.text, message, "INFO")

        formatted_caplog.clear()
        message = "DEBUG message for testing"
        logger.debug(message)
        assert len(formatted_caplog.records) == 1
        _test_formatted_log(formatted_caplog.text, message, "DEBUG")


def test_operations_formatter(formatted_caplog):

    with formatted_caplog.at_level("INFO"):
        formatted_caplog.clear()
        logger = logging.getLogger(__name__ + ":test_operations_formatter")
        logger.info(
            operations.OperationsLogEntry(
                message="Operations message for testing.",
                operation=operations.OperationsLogEntry.Operation.only_test,
                step=operations.OperationsLogEntry.Step.only_test,
                status=operations.OperationsLogEntry.Status.success,
            )
        )
        assert len(formatted_caplog.records) == 1
        _test_formatted_log(
            formatted_caplog.text,
            "Operations message for testing. status=SUCCESS operation=ONLY_TEST step=ONLY_TEST",
            "INFO",
        )
        _test_formatted_log_for_use_case(
            formatted_caplog.text,
            operations.OperationsLogEntry.Operation.only_test.value,
            operations.OperationsLogEntry.Step.only_test.value,
            operations.OperationsLogEntry.Status.success.value,
        )


def test_exception_formatter(formatted_caplog):

    logger = logging.getLogger(f"{__name__}_test_exception_formatter")

    with formatted_caplog.at_level("DEBUG"):
        formatted_caplog.clear()

        try:
            raise Exception("Test")
        except Exception:
            logger.exception("Test message")

        assert len(formatted_caplog.records) == 1
        _test_formatted_log(
            formatted_caplog.text,
            False,
            "ERROR",
        )
        assert "Traceback" in formatted_caplog.text
