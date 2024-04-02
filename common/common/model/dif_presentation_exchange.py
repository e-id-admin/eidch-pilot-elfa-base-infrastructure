# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import re
from fastapi import HTTPException
import jsonpath_ng as jsonpath

from typing import Dict, Optional, Literal
from pydantic import BaseModel


#############################
# DIF Presentation Exchange #
#############################
# TODO -> EID-1248: Move me to my own file?


class MissingAttributeException(KeyError):
    def __init__(self, attribute: str, *args: object) -> None:
        super().__init__(*args)
        self.attribute = attribute


class DIFPathNested(BaseModel):
    path: str
    format: str = Literal['jwt_vc']
    """
    The Format in which the vp token is provided. We only support jwt_vc
    """


class DIFPresentationDescriptor(BaseModel):
    id: str
    format: str = Literal['jwt_vp_json']
    """
    The format the VP is using, we only accept jwt verifiable presentations
    """
    path: Optional[str] = '$'
    path_nested: DIFPathNested


class DIFPresentationSubmission(BaseModel):
    """
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6
    The submission is a form of map for the verifier on where to find the requested data
    """

    id: str
    definition_id: str
    descriptor_map: list[DIFPresentationDescriptor]


class Filter(BaseModel):
    type: str
    pattern: str | None = None


class Constraint(BaseModel):
    path: list[str]
    filter: Filter | None = None


class Fields(BaseModel):
    fields: list[Constraint]


class InputDescriptor(BaseModel):
    """
    https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object
    """

    id: str
    format: dict
    constraints: Fields


class ClientMetadata(BaseModel):
    """
    Client Metadata
    https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    """

    client_name: str | None = None
    """
    Human-readable string name of the client.
    """

    logo_uri: str | None = None
    """
    URL string that references a logo for the client.
    """

class PresentationDefinition(BaseModel):
    """
    https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition
    """

    id: str
    input_descriptors: list[InputDescriptor]    

class RequestObject(BaseModel):
    """
    TODO -> EID-1176: This does not comply with the following spec
    https://www.rfc-editor.org/rfc/rfc9101.html#name-request-object-2
    """

    presentation_definition: PresentationDefinition
    nonce: str
    response_uri: str | None = None
    """"
    The uri where the holder needs to send the authorization response
    as post reqeust when using "direct_post" mode.
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2 
    """

    response_mode: str | None = Literal["query", "fragment", "direct_post"]
    """
    Allowed response modes. In this verifier setup "direct_post" is used, where the
    holder return the presentation submission via post body and not as appendes
    params in the redirecut_uri
    https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html#ResponseModes
    """

    state: str | None = None
    """
    State parameter to protect the response uri from inadvertent requests. This is 
    recommended especially when having multiple verifier components (front end + backend)
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-10.5 
    """

    client_metadata: ClientMetadata | None = None
    """
    Metadata of the verification client.
    https://www.rfc-editor.org/rfc/rfc7591.html#section-2
    Added to the request object in https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.7
    """

def _validate_occurrences(occurrences: list[str], pattern: str) -> None:
    """
    Validate if the the intput-descriptor occurenced matches for at leat one item
    """
    for e in occurrences:
        if re.search(f"^{pattern}$", str(e)) is not None:
            return
    raise HTTPException(status_code=400, detail=f"Presentation definition validation becuase filter {pattern} wasn't met")


def get_validated_attributes(input_descriptor: InputDescriptor, credential: dict) -> list[str]:
    """
    Get the validated attribute namens which have been requestd in the input-descriptor
    """
    constraints = input_descriptor.constraints.fields
    attributes = []
    for constraint in constraints:
        constraint_path = constraint.path[0]
        path_matches = jsonpath.parse(constraint_path).find(credential)
        if len(path_matches) < 1:
            raise MissingAttributeException(constraint_path)
        values = list(map(lambda x: x.value, path_matches))
        field_name = constraint_path.split(".")[-1]
        if constraint.filter is not None:
            # FIXME str(value) might mot be right. when not converted number checking causes error
            _validate_occurrences(values, constraint.filter.pattern)
        if constraint_path.__contains__("credentialSubject"):
            attributes.append(field_name)
    return attributes
