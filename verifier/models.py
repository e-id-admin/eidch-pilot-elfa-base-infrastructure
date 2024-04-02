# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import datetime
from enum import Enum
from typing import Optional, Self
import uuid
from pydantic import BaseModel


import common.model.dif_presentation_exchange as dif
from common.verifiable_credential import OpenID4VerifiablePresentationResponse


def get_exp_time_for(ttl: int) -> int:
    """
    Expiration time in epoche format -> required for fakeredis expireat()
    """
    return int((datetime.datetime.now() + datetime.timedelta(seconds=ttl)).timestamp())


class CacheModel(BaseModel):
    """
    Wrapper for all objects which are cached
    """

    expires_at: Optional[int] = None
    """
    Expiration time as unix epoche
    """

    def set_expires_at(self, ttl: int):
        """Set expiration time based on a time to live. ExpiresAt = (now + ttl)

        Args:
            ttl (int): time to live
        """
        self.expires_at = get_exp_time_for(ttl)


class AuthorizationResponseData(CacheModel):
    """
    DTO for the data which the holder submitted or errors which occured.
    This DTO is not part of OID4VC Standard and sent to the user of the verifier agent.
    * vp_token: token the holder submitted as part of the presentation
    * presentation_submission: data submitted by the holder
    * error_description: human readable description of the error which occured
    * error_code: detailed machine readable code for why the occured error
    """

    state: str | None = None
    vp_token: str | dict | list[str | dict] | None = None
    presentation_submission: dif.DIFPresentationSubmission | None = None
    error_description: str | None = None
    error_code: str | None = None

    @staticmethod
    def from_OpenID4VerifiablePresentationResponse(ttl: int, obj: OpenID4VerifiablePresentationResponse) -> Self:
        return AuthorizationResponseData(presentation_submission=obj.presentation_submission, state=obj.state, vp_token=obj.vp_token, expires_at=get_exp_time_for(ttl))


class VerificationRequestObject(CacheModel):
    id: str
    presentation_definition: dif.PresentationDefinition
    response_uri: str
    nonce: str
    response_mode: str
    client_metadata: dif.ClientMetadata | None = None

    @staticmethod
    def from_OpendIDRequestObject(obj: dif.RequestObject, id: str = str(uuid.uuid4())) -> Self:
        return VerificationRequestObject(
            id=id,
            presentation_definition=obj.presentation_definition,
            response_uri=obj.response_uri,
            response_mode=obj.response_mode,
            nonce=obj.nonce,
            client_metadata=obj.client_metadata,
        )

    def to_OpendIDRequestObject(self) -> dif.RequestObject:
        return dif.RequestObject(
            presentation_definition=self.presentation_definition,
            response_uri=self.response_uri,
            response_mode=self.response_mode,
            nonce=self.nonce,
            client_metadata=self.client_metadata,
        )


# TODO -> EID-1287: Implement Error-Code in addition to Verification-Status
class VerificationStatus(Enum):
    """
    Status which gives information about the status of a verification
    """

    PENDING = "PENDING"
    """
    The party which initialized the verification has send the authorization_request to the holder, but the holder hasn't submitted anything yet
    """

    SUCCESS = "SUCCESS"
    """
    The verification is done.
    """
    FAILED = "FAILED"
    """
    The content submitted by the holder lead in an error / content not valid or the verification timouted
    """


class VerificationManagement(CacheModel):
    """
    Url for the holder to fetch the authorization request
    """

    id: str
    """
    Identifier for the consumer to fetch later the authorization response data
    """
    authorization_request_object_uri: str
    authorization_request_id: str
    status: VerificationStatus


class PresentationDefinitionRequest(BaseModel):
    input_descriptors: list[dif.InputDescriptor]
    client_metadata: dif.ClientMetadata | None = None


class PresentationDefinition(CacheModel):
    id: str
    input_descriptors: list[dif.InputDescriptor]


class AuthRequestVerificationManagementPair(CacheModel):
    """
    Serves as a temporary pair to cache the mapping between verification_management object and authorization_request.
    This is due to lack of capability of the fakeRedi lib -> See verification_cache.py
    """

    authorization_request_id: str
    verification_management_id: str
