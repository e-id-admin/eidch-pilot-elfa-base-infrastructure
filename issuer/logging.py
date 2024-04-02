# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from enum import Enum

from common.logging import operations


class IssuerOperationsLogEntry(operations.OperationsLogEntry):
    """Container for issuer operations specific logging."""

    class Operation(Enum):
        issuance = "ISSUANCE"

    class Step(Enum):
        issuance_preparation = "PREPARATION"
        issuance_delivery = "DELIVERY"
        issuance_expiry = "EXPIRY"

    operation: Operation
    step: Step

    seconds_until_expiry: float | None = None
