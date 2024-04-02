# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Pydantic models according to openid specification
"""
from typing import Optional
from pydantic import BaseModel


class OpenIdConfiguration(BaseModel):
    """
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderConfigurationRequest
    and more directly to the attributes
    https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
    Also Influenced by
    https://www.ietf.org/archive/id/draft-ietf-oauth-par-03.html#as_metadata
    """

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: Optional[str] = None
    jwks_uri: str
    registration_endpoint: Optional[str] = None
    scopes_supported: Optional[str] = None
    response_types_supported: list[str]
    id_token_signing_alg_values_supported: list[str]

    request_uri_parameter_supported: Optional[bool] = None
    pushed_authorization_request_endpoint: Optional[str] = None
    # TODO -> EID-1177: Complete (at least with required parameters)
