# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Credential Issuer PoC
Using Specifications

# OpenID4VCI Draft 11
https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html

W3C Verifiable Credential
https://www.w3.org/TR/vc-data-model-2.0/

JWT
https://datatracker.ietf.org/doc/html/rfc7519

SD-JWT
https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/04/

StatusList2021
https://www.w3.org/TR/2023/WD-vc-status-list-20230427/

OpenID Connect
https://openid.net/specs/openid-connect-core-1_0.html

OAuth 2.0
https://datatracker.ietf.org/doc/html/rfc6749

OAuth 2.0 Pushed Authorization Requests
https://datatracker.ietf.org/doc/html/rfc9126
"""

# FastAPI
from asgi_correlation_id import CorrelationIdMiddleware

from common.fastapi_extensions import ExtendedFastAPI


from issuer.exception.handler import configure_exception_handlers
import issuer.route.registry as registry
import issuer.route.generic_issuer as generic
import issuer.route.admin as admin
import issuer.route.openid as openid
import issuer.route.redirect as redirect
import issuer.route.health as health
import issuer.timeout as timeout
import issuer.config as conf

app = ExtendedFastAPI(
    conf.inject,
    lifespan_functions=[timeout.midnight_cleanup_lifespan()],
)

app.include_router(registry.router)
app.include_router(generic.router)
app.include_router(admin.router)
app.include_router(redirect.router)
app.include_router(health.router)

app.add_middleware(
    CorrelationIdMiddleware,
)

TAG_CREDENTIAL_ISSUANCE = "Issuing"
TAG_OPENID = ".OpenID"
TAG_OPENID4VCI = ".OpenID4VCI"

"""
    Reason for sub application:

    To handle exceptions in an spec conform way we need to overwrite the
    exception handeling of pydantic model validation. This is only possible
    on application level, and not on router level.
    We did seperate the applications to not overwrite the exception
    handeling for the other routes.
"""
openid_app = ExtendedFastAPI(conf.inject, title="Openid conform issuer")
openid_app.include_router(openid.router)
configure_exception_handlers(openid_app)
app.mount(
    "",
    openid_app,
)
# Existing Routes are not overwritten. We just add in the OpenAPI docs...
app.include_router(openid.router)
