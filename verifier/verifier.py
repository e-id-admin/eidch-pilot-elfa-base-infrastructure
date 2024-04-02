# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Credential Issuer PoC
Using Specifications

OpenID4VP Version 1.0.18
https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html

W3C Verifiable Credential
https://www.w3.org/TR/vc-data-model-2.0/

SD-JWT
https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/04/

"""

# FastAPI
from asgi_correlation_id import CorrelationIdMiddleware

from common.fastapi_extensions import ExtendedFastAPI

from verifier.exception.handler import configure_exception_handlers

import verifier.route.generic_verifier as generic
import verifier.route.openid as openid
import verifier.route.health as health

from verifier import config as conf


app = ExtendedFastAPI(conf.inject)
app.include_router(generic.router)
app.include_router(health.router)

TAG_REGISTRY = "Registry"
TAG_CREDENTIAL_ISSUANCE = "Issuing"
TAG_CREDENTIAL_VERIFICATION = "Verification"
VERIFIABLE_PRESENTAION = "Presentation"
TAG_OPENID = ".OpenID"

app.add_middleware(CorrelationIdMiddleware)


"""
    Reason for sub application:
    To handle exceptions in an spec conform way we need to overwrite the
    exception handeling of pydantic model validation. This is only possible
    on application level, and not on router level.
    We did seperate the applications to not overwrite the exception
    handeling for the other routes.
"""
openid_app = ExtendedFastAPI(conf.inject, title="OpenID conform verifier")

openid_app.include_router(openid.router)
configure_exception_handlers(openid_app, conf.inject())
app.mount(
    "",
    openid_app,
)
# Existing Routes are not overwritten. We just add in the OpenAPI docs...
app.include_router(openid.router)
