# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Based on (outdated) https://www.w3.org/TR/2023/WD-vc-data-model-2.0-20230829/
TODO -> EID-1165: Update
"""

import time
import datetime
from typing import Optional, Literal, Union
from functools import cached_property

from pydantic import BaseModel, ConfigDict, ValidationInfo
from pydantic import computed_field, field_validator, Field

from common.model import ietf
from common.parsing import object_from_url_safe
from common import jwt_utils

import common.model.dif_presentation_exchange as dif


##########################
# Openid Issuer Metadata #
##########################


class MetadataDisplayLogo(BaseModel):
    """information about the logo of the Credential with a following non-exhaustive list of parameters that MAY be included"""

    model_config = ConfigDict(extra='allow')

    url: Optional[str] = None
    alt_text: Optional[str] = None


class MetadataDisplay(BaseModel):
    """
    Supporting Dataclass for display objects
    Version:openid-4-verifiable-credential-issuance-1_0-11
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata-2
    """

    model_config = ConfigDict(extra='allow')

    name: Optional[str] = None
    locale: Optional[str] = None
    logo: Optional[MetadataDisplayLogo] = None
    description: Optional[str] = None
    background_color: Optional[str] = None
    text_color: Optional[str] = None


class MetadataCredentialSubjectField(BaseModel):
    """
    The following additional Credential Issuer metadata are defined for this Credential format.

    Version:openid-4-verifiable-credential-issuance-1_0-11
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata-2
    """

    mandatory: Optional[bool] = None
    """
    Indicates if the field must be present. If omitted its default should be assumed false
    """
    value_type: Optional[str] = None
    """
    One of string, number or image media type such as image/jpeg, image/png
    """
    display: Optional[list[dict[str, str]]] = None
    """
    Information on what and how to display. Non-exhaustive list in specification
    Can contain name & locale
    """


class MetadataCredentialDefinition(BaseModel):
    """
    Version:openid-4-verifiable-credential-issuance-1_0-11
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-credential-issuer-metadata-2
    When the format value is jwt_vc_json, entire Credential Offer, Authorization Details, Credential Request and Credential Issuer metadata,
    including credential_definition object, MUST NOT be processed using JSON-LD rules.
    """

    type: list[str]
    """
    designating the types a certain credential type supports according to VC_DATA, Section 4.3
    https://www.w3.org/TR/2022/REC-vc-data-model-20220303/#types
    Note: Version 13 OID4VCI is type (singular), version 11 is types (plural)
    We use Version 13
    """
    credentialSubject: Optional[dict[str, dict | MetadataCredentialSubjectField]] = None
    """
    eg. "fieldname": {"mandatory": True, "value_type":"number"}
    """


class MetadataCredentialSupported(BaseModel):
    """
    Class assisting in creating the credential support format
    version: openid-4-verifiable-credential-issuance-1_0-11
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#section-10.2.3.1
    """

    format: str = "jwt_vc_json"
    """
    Identifying the format of the credential, eg: jwt_vc_json or ldp_vc
    """
    scope: Optional[str] = None
    cryptographic_binding_methods_supported: Optional[list[str]] = None
    """
    The holder binding methods supported by the credential endpoint, case sensitive
    if did must be did:did_type eg: did:jwk
    """
    cryptographic_suites_supported: Optional[list[str]] = None
    """
    The suites supported by the by the issuer for holder binding
    """
    proof_types_supported: Optional[list[str]] = None
    """
    If not provided, the holder should assume it's jwt
    """
    display: Optional[list[MetadataDisplay]] = None

    credential_definition: MetadataCredentialDefinition
    """
    Not optional for jwt_vc_json
    """

    order: Optional[list[str]] = None
    """
    List of the claim fieldnames in the order they should be displayed by the wallet
    E.1.1.2. Credential Issuer Metadata
    """


class OpenIDCredentialIssuerData(BaseModel):
    """
    OpenID4VCI Metadata as defined in
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-10.2.3
    * credential_issuer: The Credential Issuer's identifier
    * authorization_server: Identifier of the OAuth 2.0 Authorization Server
    * credential_endpoint: URL of the Credential Issuer's Credential Endpoint
    * batch_credential_endpoint:  URL of the Credential Issuer's Batch Credential Endpoint. If omitted, the Credential Issuer does not support the Batch Credential Issuance
    * credentials_supported: metadata about a separate credential type that the Credential Issuer can issue.
    * display: contains display properties of a Credential Issuer for a certain language.

    """

    credential_issuer: str
    authorization_server: Optional[str] = None
    credential_endpoint: str
    batch_credential_endpoint: Optional[str] = None
    credentials_supported: dict[str, MetadataCredentialSupported]
    """
    Credentail Supported with Unique identifier for the credential issued,
    as used in the credential offer as key.
    """
    display: Optional[list[MetadataDisplay]] = None


##############
# Credential #
##############


class CredentialStatus(BaseModel):
    id: str
    """
    The value of the id property MUST be a URL which MAY be dereferenced.
    """
    type: str
    """
    Must express the credential status type, eg StatusList2021Entry
    """


class StatusList2021Entry(CredentialStatus):
    """
    https://www.w3.org/TR/2023/WD-vc-status-list-20230427/#statuslist2021entry
    id is expected to be a URL that identifies the status information associated with the verifiable credential.
    id must not be the url for the status list.
    """

    type: str | list[str]  # = [Literal['VerifiableCredential'], Literal['StatusList2021Entry'],] #TODO This is not correctly enforced. Find out how to enforce it...
    statusPurpose: str
    statusListIndex: str
    """
    an arbitrary size integer greater than or equal to 0, expressed as a string
    identifies the bit position of the status of the verifiable credential
    """
    statusListCredential: str
    """
    MUST be a URL to a verifiable credential
    resulting verifiable credential MUST have type property that includes the StatusList2021Credential value
    """


class CredentialSubject(BaseModel):
    """
    The actual data of the credential
    https://www.w3.org/TR/vc-data-model-2.0/#credential-subject
    Ideally parsed further using the information from the w3c data type
    """

    model_config = ConfigDict(extra='allow')

    id: Optional[str] = None
    """
    Each CredentialSubject may contain an id. if it contains it, the id should be unique
    The value of the id property MUST be a URL which MAY be dereferenced.
    """


class W3CData(BaseModel):
    # TODO -> EID-1166: add @context
    """
    https://www.w3.org/TR/vc-data-model-2.0
    """
    model_config = ConfigDict(extra='allow')

    id: Optional[str] = None
    """
    A globally unique identifier
    If jti is set this has to be None
    The value of the id property MUST be a URL which MAY be dereferenced.
    https://www.w3.org/TR/vc-data-model-2.0/#identifiers
    """

    type: list[str] | str
    """
    Verifiable credentials and verifiable presentations MUST have a type property.
    The value of the type property MUST be, or map to (through interpretation of the @context property), one or more URLs.
    https://www.w3.org/TR/vc-data-model-2.0/#types
    """

    validFrom: Optional[str] = None
    """
    XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
    eg. 2010-01-01T19:23:24Z
    """

    validUntil: Optional[str] = None
    """
    XMLSchema dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
    eg. 2010-01-01T19:23:24Z
    """

    @field_validator("validFrom", "validUntil")
    @classmethod
    def validate_xmlschema_date(cls, date_value: str, info: ValidationInfo):
        """Ensur the values are XMLSchema dateTimeStamp conform"""
        if not date_value:
            # Optional Field - if not set do not check
            return date_value
        try:
            datetime.datetime.fromisoformat(date_value)
        except ValueError:
            raise ValueError(f"{info.field_name} must be XMLSchmea dateTimeStamp (ISO8601) format.")
        return date_value

    # TODO -> EID-1167: Handle LD-Proof Credentials https://www.w3.org/TR/vc-data-model-2.0/#securing-verifiable-credentials

    @computed_field(repr=False)
    @cached_property
    def type_document(self) -> dict:
        """
        Derefenced type, using either @context or the url provided in the type field
        Performs a call to fetch the document in question
        """
        # TODO -> EID-1166: Get the documents, find out how to use em.
        return

    def is_date_valid(self) -> bool:
        # Note: Requires python 3.11
        def date_in_future(date: str):
            """Compare if the date is in the future"""
            validity_date = datetime.datetime.fromisoformat(date)
            now = datetime.datetime.now(validity_date.tzinfo)
            return validity_date > now

        if self.validUntil:
            expired = not date_in_future(self.validUntil)
        else:
            expired = False

        if self.validFrom:
            premature = date_in_future(self.validFrom)
        else:
            premature = False

        return not premature and not expired


class VerifiableCredential(W3CData):
    """
    https://www.w3.org/TR/vc-data-model-2.0/
    """

    issuer: str | dict
    """
    MUST be either a URL or an object containing an id property.
    if dereferenced, results in a document that can be used to
    verify the information expressed in the credential
    """

    credentialSubject: CredentialSubject | list[CredentialSubject]

    # Extend this Pydanitc Field like follows
    # credentialStatus: Union[StatusList2021Entry, MyOtherCredentialStatus] = Field(discriminator='type')
    credentialStatus: Union[StatusList2021Entry, list[StatusList2021Entry], None] = None
    """
    Discriminated using type field.
    """


class VerifiablePresentation(W3CData):
    """
    https://www.w3.org/TR/vc-data-model-2.0/#presentations-0
    """

    verifiableCredential: Union[str, VerifiableCredential, list[str | VerifiableCredential]]
    """
    List of Credentials, either as jwts or objects
    """
    type: str | list[str] = "VerifiablePresentation"


class JsonWebTokenHead(BaseModel):
    """
    JWT
    https://datatracker.ietf.org/doc/html/rfc7519#section-5
    JSON Web Signature (JWS)
    https://www.rfc-editor.org/rfc/rfc7515.html
    JSON Web Encryption (JWE)
    https://www.rfc-editor.org/rfc/rfc7516.html

    """

    typ: Optional[str] = None
    """
    used to declare the media type.  If present, it is RECOMMENDED that its value be "JWT" (Note: In OpenID4VC it's not!)
    """
    cty: Optional[str] = None

    alg: Optional[str] = None
    """
    Algorithm: identifies the cryptographic algorithm used to sign the jwt
    """
    jku: Optional[str] = None
    """
    Json Web Key Set URL; Where to find the JWK (Probably not used)
    """
    jwk: Optional[str] = None
    """
    Json Web Key
    """

    # TODO -> EID-1174: Find out how to add w3c data fields like kid?


class JsonWebTokenBody(BaseModel):
    """
    https://datatracker.ietf.org/doc/html/rfc7519#section-4
    NumericDate: number of seconds from 1970-01-01T00:00:00Z UTC
    """

    model_config = ConfigDict(extra='allow')  # Store extra data as well
    iss: Optional[str] = None
    """
    Issuer: identifies the principal that issued the JWT. Case Sensitive. StringOrURI
    """
    sub: Optional[str] = None
    """
    Subject: identifies the principal that is the subject of the JWT StringOrURI
    """
    aud: Union[str, list[str], None] = None
    """
    Audience: identifies the recipients that the JWT is intended for - list of StringOrURI
    """
    exp: Optional[int] = None
    """
    Expiration Time: identifies the time on or after the jwt must not be accepted for processing NumericDate
    """
    nbf: Optional[int] = None
    """
    Not Before: the time before which the JWT MUST NOT be accepted for processing NumericDate
    """
    iat: Optional[int] = None
    """
    Issued at: the time at which the JWT was issued NumericDate
    """
    jti: Optional[str] = None
    """
    JWT ID: unique identifier for the jwt. can be used to prevent jwts from being replayed
    """

    cnf: Optional[ietf.JsonWebTokenConfirmation] = None
    """
    https://www.rfc-editor.org/rfc/rfc7800.html#section-3.1
    Confirmation Claim: The "cnf" claim is used in the JWT to contain members used to identify the proof-of-possession key.

    This is required when using holder binding.
    https://datatracker.ietf.org/doc/html/draft-terbu-sd-jwt-vc-02#section-4.2.2.2
    """

    def is_date_valid(self) -> bool:
        """
        Validates exp & nbf, if exist
        """
        exp_valid = not self.exp or (self.exp > time.time())
        nbf_valid = not self.nbf or (self.nbf < time.time())
        return exp_valid and nbf_valid


class JsonWebTokenBodyVCData(JsonWebTokenBody):
    # TODO -> EID-1248: Split?
    """
    https://www.w3.org/standards/history/vc-jose-cose/
    https://www.w3.org/TR/vc-data-model-2.0/#json-web-token-extensions
    """
    vc: Optional[VerifiableCredential] = None
    """
    JSON object, which MUST be present in a JWT verifiable credential. The object contains the credential
    https://www.w3.org/TR/vc-data-model-2.0/#json-web-token-extensions
    """
    vp: Optional[VerifiablePresentation] = None
    """
    JSON object, which MUST be present in a JWT verifiable presentation. The object contains the presentation
    https://www.w3.org/TR/vc-data-model-2.0//#vp-json-web-token-claim
    Note: Probably Depricated
    """

    nonce: Optional[str] = None
    """Nonce for Verifiable Presentation"""

    # @computed_field(repr=False)
    # @cached_property
    # def verifiable_credential(self) -> VerifiableCredential:
    #     return VerifiableCredential(**self.vc)

    # @computed_field(repr=False)
    # @cached_property
    # def verifiable_presentation(self) -> VerifiablePresentation:
    #     return VerifiablePresentation(**self.vp)


def _jwt_to_dictionary(jwt: str):
    """
    Converts a jwt to a dictionary
    """
    credential_parts = jwt_utils.split_jwt(jwt)
    return {"head_base64": credential_parts[0], "body_base64": credential_parts[1], "signature": credential_parts[2]}


def _sd_jwt_to_dictionary(sd_jwt: str):
    """
    Converts a sd_jwt to a dictionary
    """
    sd_jwt_dict = _jwt_to_dictionary(jwt_utils.get_jwt_of_sdjwt(sd_jwt))
    sd_jwt_dict["sd_secrets_base64"] = jwt_utils.get_secrets_of_sdjwt(sd_jwt)
    return sd_jwt_dict


class JsonWebToken(BaseModel):
    """
    Wrapper to acess JWT body / head / signature.
    The information required to check the signature is contained further in the jwt data.
    https://datatracker.ietf.org/doc/html/rfc7519
    """

    head_base64: str
    body_base64: str
    signature: str

    @staticmethod
    def from_str(jwt_base64: str) -> "JsonWebToken":
        return JsonWebToken(**_jwt_to_dictionary(jwt_base64))

    @computed_field(repr=False)
    @cached_property
    def head(self) -> JsonWebTokenHead:
        return JsonWebTokenHead(**self.head_dict)

    @computed_field(repr=False)
    @cached_property
    def body(self) -> JsonWebTokenBody:
        if 'vc' in self.body_dict or 'vp' in self.body_dict:
            return JsonWebTokenBodyVCData(**self.body_dict)
        return JsonWebTokenBody(**self.body_dict)

    @cached_property
    def head_dict(self) -> dict:
        return object_from_url_safe(self.head_base64)

    @cached_property
    def body_dict(self) -> dict:
        return object_from_url_safe(self.body_base64)

    def to_raw(self):
        return ".".join([self.head_base64, self.body_base64, self.signature])


class SelectiveDisclosureClaimString(str):
    """
    https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.html#name-data-formats
    """

    @field_validator('data')
    def validate(cls, data):
        assert len(data) == 3  # check if all selective disclosures have three elements (salt, atrribute, value)
        return data

    @cached_property
    def data(self) -> list[str]:
        return object_from_url_safe(self)

    @computed_field(repr=False)
    @cached_property
    def salt(self) -> str:
        return self.data[0]

    @computed_field(repr=False)
    @cached_property
    def attribute_name(self) -> str:
        return self.data[1]

    @computed_field(repr=False)
    @cached_property
    def attribute_value(self) -> str:  # TODO -> EID-1175: could be a json and not only a string
        return self.data[2]

    @computed_field(repr=False)
    @cached_property
    def hash(self) -> str:
        return jwt_utils.hash(self.encode())


class SelectiveDisclosureJsonWebToken(JsonWebToken):
    """
    https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-05.htm
    """

    sd_secrets_base64: Optional[list[str]] = None

    @staticmethod
    def from_str(sd_jwt_base64: str) -> "SelectiveDisclosureJsonWebToken":
        return SelectiveDisclosureJsonWebToken(**_sd_jwt_to_dictionary(sd_jwt_base64))

    @computed_field(repr=False)
    @cached_property
    def jwt(self) -> JsonWebToken:
        jwt = jwt_utils.get_jwt_of_sdjwt(self.to_raw())
        return JsonWebToken(**_jwt_to_dictionary(jwt))

    @computed_field(repr=False)
    @cached_property
    def sd_secrets(self) -> list[str]:
        # sd_secret[0] is the salt, sd_secret[1] is the attribute name, sd_secret[2] is the attribute value
        # TODO -> EID-1175: value could also be a json.
        if not self.sd_secrets_base64:
            return []
        _sd_secret = [SelectiveDisclosureClaimString(sd) for sd in self.sd_secrets_base64]
        return [(secret.salt, secret.attribute_name, secret.attribute_value) for secret in _sd_secret]

    @cached_property
    def body_dict(self) -> dict:
        # Returns the body dict where the sd_secrets are replaced with the actual secrets
        body_dict = super().body_dict
        if not self.sd_secrets_base64:
            return body_dict
        unpacked = jwt_utils.SDJWT_Unpacker(self.to_raw()).extract_sd_claims()
        original = self.jwt.body_dict
        return jwt_utils.deep_merge(unpacked, original)

    @computed_field(repr=False)
    @cached_property
    def body(self) -> JsonWebTokenBodyVCData:
        if not ('vc' in self.body_dict or 'vp' in self.body_dict):
            raise ValueError("Selective disclosure makes only sense if you have a vc or vp where one wants to disclose some claims")
        return JsonWebTokenBodyVCData(**self.body_dict)

    def to_raw(self) -> str:
        jwt = super().to_raw()
        return jwt_utils.compose_sd_jwt(jwt, self.sd_secrets_base64)


class OpenID4VerifiableCredentialJWT(BaseModel):
    format: str = Literal['jwt_vc']
    """Should be jwt_vc"""
    credential: str
    """
    Credential as JWT or SD-JWT
    """

    @field_validator('credential')
    def validate(cls, credential):
        if jwt_utils.is_sd_jwt(credential):
            SelectiveDisclosureJsonWebToken.model_validate(SelectiveDisclosureJsonWebToken.from_str(credential))
        else:
            JsonWebToken.model_validate(JsonWebToken.from_str(credential))
        return credential

    @cached_property
    def jwt(self) -> Union[JsonWebToken, SelectiveDisclosureJsonWebToken]:
        if jwt_utils.is_sd_jwt(self.credential):
            return SelectiveDisclosureJsonWebToken.from_str(self.credential)
        return JsonWebToken.from_str(self.credential)


class OpenID4VerifiablePresentationTokenJWT(JsonWebToken):
    pass


class OpenID4VerifiablePresentationResponse(BaseModel):
    """
    https://openid.net/specs/openid-4-verifiable-presentations-1_0-18.html#section-6.1
    """

    state: str | None = None
    """
    State which represents the request-id as mentionded here
    https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-response-mode-direct_post-2
    """

    vp_token: str | dict | list[str | dict]
    """
    JSON String or JSON object that MUST contain a single Verifiable Presentation
    or an array of JSON Strings and JSON objects each of them containing a Verifiable Presentations.

    Each Verifiable Presentation MUST be represented as a JSON string (that is a Base64url encoded value)
    or a JSON object depending on a format as defined in Annex E of [OpenID.VCI]
    >> for example for jwt_vc_json it's a string
    """

    presentation_submission: dif.DIFPresentationSubmission
    """
    contains mappings between the requested Verifiable Credentials and where to find them within the returned VP Token
    """

    @cached_property
    def vp_token_jwt(self) -> JsonWebToken:
        assert isinstance(self.vp_token, str), "Only works for a single vp"
        return JsonWebToken.from_str(self.vp_token)


###############################
# OpenID4VCI Credential Offer #
###############################
class OfferAuthorizationCode(BaseModel):
    issuer_state: Optional[str] = None
    """
    used to bind the subsequent Authorization Request with the Credential Issuer to a context set up during previous steps
    """


class OfferPreauthorizedGrantType(BaseModel):
    pre_auth_code: str = Field(alias="pre-authorized_code")
    """
    The pre-authorized code used for requesting the token
    """
    user_pin_required: Optional[bool] = None
    """
    Does the pre-auth code come with a pin (provided by a differnt way)
    """
    interval: Optional[int] = None
    """
    Minimum time the wallet should wait between polling attempts
    """


class CredentialOfferGrant(BaseModel):
    authorization_code: Optional[OfferAuthorizationCode] = None
    grant_type: OfferPreauthorizedGrantType = Field(alias="urn:ietf:params:oauth:grant-type:pre-authorized_code")


class CredentialOfferParameters(BaseModel):
    """
    4.1.1 Credential Offer Parameters
    According Version 13
    """

    credential_issuer: str
    """
    The URL of the Credential Issuer from which the Wallet is requested to obtain one or more Credentials
    """

    credentials: list[str | MetadataCredentialSupported]
    """
    If string, the string MUST be one of the scope values of credentials_supported
    """

    grants: Optional[CredentialOfferGrant] = None
