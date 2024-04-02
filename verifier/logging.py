# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from enum import Enum

from common.logging import operations


class VerifierOperationsLogEntry(operations.OperationsLogEntry):
    """Container for verifier operations specific logging."""

    class Operation(Enum):
        verification = "VERIFICATION"

    class Step(Enum):
        verification_request = "REQUEST"
        verification_evaluation = "EVALUATION"
        verification_response = "RESPONSE"

    operation: Operation
    step: Step

    error_code: str | None = None
