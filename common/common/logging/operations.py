# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from enum import Enum
from uuid import UUID
from common.logging import splunk


class OperationsLogEntry(splunk.SplunkExtendedLogEntry):
    """Container for operations specific logging."""

    class Status(Enum):
        """Enum detailing the state operations can be in."""

        success = "SUCCESS"
        error = "ERROR"

    class Operation(Enum):
        """
        Enum detailing which operations the component supports.

        As enums cannot inherit from each other this one is merely existing
        to force inherited classes to overwrite and define this enum.
        """

        only_test = "ONLY_TEST"

    class Step(Enum):
        """
        Enum detailing which steps in the operations are available.

        Suggested naming format: <operation>_<step>

        As enums cannot inherit from each other this one is merely existing
        to force inherited classes to overwrite and define this enum.
        """

        only_test = "ONLY_TEST"

    status: Status
    operation: Operation
    step: Step
    management_id: str | UUID | None = None
