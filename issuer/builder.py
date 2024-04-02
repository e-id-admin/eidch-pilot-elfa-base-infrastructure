# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid
import time
import re
import logging

from sd_jwt.common import SDObj as _SDObj
from common.key_configuration import KeyConfiguration
from common import jwt_utils

from common import verifiable_credential as vc
from common.model import ietf

import issuer.config as conf
import issuer.statuslist2021 as registry


class SDObj(_SDObj, str):
    """
    Wrapper so pydantic can parse SDObj to ensure the VC structure is correct
    """

    pass


def convert_to_sd_jwt(data: dict) -> dict:
    """
    Loop through credential data and form it for SD-JWT conversion (creates SDObj out of keys & values)
    If element is another dictionary, will loop through these elements recursively.
    """
    # TODO -> EID-1184: Make me some form of configurable parameter
    RECURSION_EXCLUDED_KEY_REGEX = [r".*Image"]

    def key_recusion_excluded(key: str):
        for exclusion_regex in RECURSION_EXCLUDED_KEY_REGEX:
            if re.match(exclusion_regex, key):
                return True

    def needs_recursion(value: any):
        return type(value) is dict  # TODO -> EID-1243: also recurse if it is a list

    def convert(dict_item):
        key, value = dict_item
        if needs_recursion(value) and not key_recusion_excluded(key):
            return (key, convert_to_sd_jwt(value))
        return (SDObj(key), value)

    return dict(map(convert, data.items()))


def jwt_from_dict(raw_jwt: vc.JsonWebTokenBody, key_conf: KeyConfiguration) -> str:
    """
    Returns a JWT from a JsonWebTokenBody.
    """
    payload = raw_jwt.model_dump(exclude_none=True)
    return key_conf.encode_jwt(payload=payload, header={"typ": "vc+jwt"})


def sd_jwt_from_dict(raw_jwt: vc.JsonWebTokenBody, credential_subject_data: dict, key_conf: KeyConfiguration) -> str:
    """
    Returns a SD-JWT from a JsonWebTokenBody
    """
    # Dump using pydantic causes the SDObj (which inherit from both str & _SDObj) to be dumped as str only
    jwt_dict = raw_jwt.model_dump(exclude_none=True)
    # We override the dumped credentialSubject with the original pre-dump data
    jwt_dict['vc']['credentialSubject'] = credential_subject_data

    return key_conf.encode_sd_jwt(jwt_dict)
    # TODO -> EID-1233 Header typ is not set correctly. Pull request already exists on GitHub.e


class VerifiableCredentialBuilder:
    def __init__(
        self,
        credential_subject_data: dict,
        config: conf.IssuerConfig,
        credential_type: list[str] = None,
        valid_from: str = None,
        valid_until: str = None,
        vc_id: str = None,
        jwt_id: str = None,
        holder_id: str | ietf.JSONWebKey = None,
    ):
        """
        credential_subject_data: all the claims (business data) for verifiable credential https://www.w3.org/TR/vc-data-model-2.0/#credential-subject
        eg: {
            "grade": 5.7,
            "degree": {
                "type": "ExampleBachelorDegree",
                "name": "Bachelor of Science and Arts"
            }
        }

        credential_type: [Optional] a list of types which can be used during validation https://www.w3.org/TR/vc-data-model-2.0/#types

        validity -- https://www.w3.org/TR/vc-data-model-2.0/#validity-period
        must be an XMLSCHEMA11-2 dateTimeStamp https://www.w3.org/TR/xmlschema11-2/#dateTimeStamp
         * valid_from: [optional] the time when the VC will be valid
         * valid_until: [optional] if exists must be greater than valid_from

        vc_id: unique identifier for the VC. https://www.w3.org/TR/vc-data-model-2.0/#identifiers

        credential_schema: [optional] schema definition https://www.w3.org/TR/vc-data-model-2.0/#data-schemas

        holder_id: holder binding identifier. Can be a DID or JWK
        """
        self.credential_subject_data = credential_subject_data
        self.credential_type = credential_type
        self.valid_from = valid_from
        self.valid_until = valid_until
        # TODO -> EID-1252: Maybe use management id here?
        self.verifiable_credential_id = f'{config.external_url}/{uuid.uuid4()}' if vc_id is None else vc_id
        self.holder_id = holder_id
        self.status_map: dict = {}
        self.jwt_id = jwt_id if jwt_id else str(uuid.uuid4())
        self.issuer_config = config

    def _get_holder_jwk_or_none(self) -> ietf.JsonWebTokenConfirmation | None:
        """
        Returns the holder jwk if it exists
        """
        if self.holder_id is None:
            return None
        if type(self.holder_id) is ietf.JSONWebKey:
            return ietf.JsonWebTokenConfirmation(jwk=self.holder_id)
        if type(self.holder_id) is str:
            if self.holder_id.startswith("did:jwk:"):
                return ietf.JsonWebTokenConfirmation(jwk=jwt_utils.get_jwk_from_did_jwk(self.holder_id))
            raise ValueError(f"Holder id is not a did:key and not a JSONWebKey: {self.holder_id}")

    def _is_sd(self):
        """
        If we have SDObj in the credential_subject_data the VerifiableCredential is
        to be created as selective disclosure
        """

        def _rec_any_sd_obj(dict_item):
            if type(dict_item) is list:
                return any(map(_rec_any_sd_obj, dict_item))
            if type(dict_item[0]) is SDObj:
                return True
            if type(dict_item[1]) is dict:
                return any(map(_rec_any_sd_obj, dict_item[1].items()))
            return False

        return any(map(_rec_any_sd_obj, self.credential_subject_data.items()))

    def create_verifiable_credential(self) -> vc.VerifiableCredential:
        """
        Creates a https://www.w3.org/TR/vc-data-model-2.0/ vc as a dictionary
        """

        # TODO -> EID-1166: add @context
        return vc.VerifiableCredential(
            id=self.jwt_id,
            type=self.credential_type,
            issuer=self.issuer_config.get_key_registry_uri(),
            credentialSubject=self.credential_subject_data,
            validFrom=self.valid_from,
            validUntil=self.valid_until,
        )

    def create_oid_jwt(
        self,
        session,
        key_conf: KeyConfiguration,
        valid_until_timestamp: int = None,
        add_status: bool = True,
    ) -> vc.OpenID4VerifiableCredentialJWT:
        """
        Creates a signed jwt
        valid_until_timestamp: POSIX Timestamp,
        if non provided not set expire date
        """
        verifiable_credential: vc.VerifiableCredential = self.create_verifiable_credential()

        raw_jwt = vc.JsonWebTokenBody(
            iss=verifiable_credential.issuer,
            iat=round(time.time()),
            jti=self.jwt_id,
            sub=self.holder_id,
            vc=verifiable_credential,
            cnf=self._get_holder_jwk_or_none(),
        )
        if valid_until_timestamp:
            raw_jwt.exp = valid_until_timestamp
        if add_status:
            self.status_map = {
                status_list_id: registry.create_credential_status(session, self.issuer_config, purpose) for purpose, status_list_id in self.issuer_config.status_list_map.items()
            }
            verifiable_credential.credentialStatus = list(self.status_map.values())

        if self._is_sd():
            logging.info("credentailSubject is for SD-JWT")
            jwt = sd_jwt_from_dict(raw_jwt, self.credential_subject_data, key_conf)
        else:
            logging.info("credentailSubject is for JWT")
            jwt = jwt_from_dict(raw_jwt, key_conf)
        # https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#section-7.3
        return vc.OpenID4VerifiableCredentialJWT(
            format="jwt_vc",
            credential=jwt,
            # TODO -> EID-1244: Add renewal nonce [Optional]
        )
