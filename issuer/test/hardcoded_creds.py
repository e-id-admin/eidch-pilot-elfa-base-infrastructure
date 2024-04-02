# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Dummy Credentials for implementation of holder & verifier router
"""

import random
import datetime

import common.verifiable_credential as vc

##################
# JWT Credential #
##################


def jwt_credential_info() -> tuple[str, vc.MetadataCredentialSupported]:
    """
    Information issuance metadata
    https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0-11.html#name-objects-comprising-credenti
    Returns unique credential identifier and the associated credential description.
    """
    credential_definition = vc.MetadataCredentialDefinition(
        type=['VerifiableCredential', 'UniversityDegreeCredential'],
        credentialSubject={
            "degree": {
                "type": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Abschluss Typ"}]),
                "name": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Diplomtitle"}]),
                "average_grade": vc.MetadataCredentialSubjectField(mandatory=True, value_type="number", display=[{"locale": "de-CH", "name": "Notendurchschnitt"}]),
            }
        },
    )
    return "tergum_dummy_jwt", vc.MetadataCredentialSupported(
        format='jwt_vc_json',
        cryptogrpahic_binding_methods_support=['did:jwk'],
        cryptographic_suites_supported=['ES256', 'ES512'],
        proof_types_supported=['jwt'],
        credential_definition=credential_definition,
    )


def get_random_degree_credential_data():
    random_degree = random.sample(["Bachelor of Science", "Bachelor of Arts", "Master of Science", "Master of Arts"], 1)[0]

    credential_subject_data = {
        "degree": {"type": "BachelorDegree" if "Bachelor" in random_degree else "MasterDegree", "name": random_degree, "average_grade": round(random.random() * 2 + 4, 2)}
    }

    return credential_subject_data


#####################
# SD-JWT Credential #
#####################
def sd_jwt_credential_info() -> tuple[str, vc.MetadataCredentialSupported]:
    """Returns unique credential identifier and the associated credential description."""
    _, metadata = jwt_credential_info()
    return "sd_tergum_dummy_jwt", metadata


########################
# SD-JWT ID-Credential #
########################


def get_oid_id_sd_jwt() -> vc.OpenID4VerifiableCredentialJWT:
    """
    Creates random pseudo ID credential subject data
    """
    birthday = datetime.date(random.randint(0, 70) + 1940, 1, 1)
    age = (datetime.datetime.now().date() - birthday).days / 365
    return {
        "given_name": random.sample(["John", "Jane"], 1)[0],
        "family_name": "Doe",
        "birthday": birthday.isoformat(),
        "address": {"street_address": f"Dummystr {random.randint(1, 10)}", "locality": "Dummytown", "country": "Dummyland"},
        "is_over_18": age > 18,
        "is_over_21": age > 21,
        "is_over_65": age > 65,
    }


def sd_jwt_id_credential_info() -> tuple[str, vc.MetadataCredentialSupported]:
    """Returns unique credential identifier and the associated credential description."""
    credential_definition = vc.MetadataCredentialDefinition(
        type=["VerifiableCredential", "IdentityCredential"],
        credentialSubject={
            "given_name": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Vorname"}]),
            "family_name": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Nachname"}]),
            "birthday": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Geburtstag"}]),
            "address": {
                "street_address": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Adresse"}]),
                "locality": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Ortschaft"}]),
                "country": vc.MetadataCredentialSubjectField(mandatory=True, value_type="string", display=[{"locale": "de-CH", "name": "Land"}]),
            },
            "is_over_18": vc.MetadataCredentialSubjectField(mandatory=True, value_type="boolean", display=[{"locale": "de-CH", "name": "Über 18"}]),
            "is_over_21": vc.MetadataCredentialSubjectField(mandatory=True, value_type="boolean", display=[{"locale": "de-CH", "name": "Über 21"}]),
            "is_over_65": vc.MetadataCredentialSubjectField(mandatory=True, value_type="boolean", display=[{"locale": "de-CH", "name": "Über 65"}]),
        },
    )
    return "sd_tergum_dummy_id_sd_jwt", vc.MetadataCredentialSupported(
        format='jwt_vc_json',
        cryptogrpahic_binding_methods_support=['did:jwk'],
        cryptographic_suites_supported=['ES256', 'ES512'],
        proof_types_supported=['jwt'],
        credential_definition=credential_definition,
    )
