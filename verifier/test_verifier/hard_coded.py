# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import uuid


import common.model.dif_presentation_exchange as dif
from verifier import models
import verifier.exception.authorization_request_errors as ex


def get_dummy_elfa_input_descriptor() -> dif.InputDescriptor:
    return dif.InputDescriptor(
        id="ELFA",
        format={
            "jwt_vc": {
                "alg": "ES512",
            }
        },
        constraints=dif.Fields(
            fields=[
                dif.Constraint(path=["$.vc.type[*]"], filter=dif.Filter(type="string", pattern="ELFA")),
                dif.Constraint(path=["$.vc.credentialSubject.lastName"]),
                dif.Constraint(path=["$.vc.credentialSubject.firstName"]),
                dif.Constraint(path=["$.vc.credentialSubject.dateOfBirth"]),
                dif.Constraint(path=["$.vc.credentialSubject.faberPin"]),
            ]
        ),
    )


def get_dummy_university_input_descriptor() -> dif.InputDescriptor:
    return dif.InputDescriptor(
        id="Bachelors Degree",
        format={
            "jwt_vc": {
                "alg": "ES512",
            }
        },
        constraints=dif.Fields(
            fields=[
                dif.Constraint(path=["$.vc.type[*]"], filter=dif.Filter(type="string", pattern="UniversityDegreeCredential")),
                dif.Constraint(path=["$.vc.credentialSubject.degree.average_grade"]),
            ]
        ),
    )


def get_presentation_definition(id: int) -> models.PresentationDefinition:
    match id:
        case 1:
            input_descriptor = get_dummy_university_input_descriptor()
        case 2:
            input_descriptor = get_dummy_elfa_input_descriptor()
        case _:
            raise ex.PresentationDefinitionNotFoundError()

    return models.PresentationDefinition(id=str(uuid.uuid4()), input_descriptors=[input_descriptor])


def get_dummy_client_metadata(id: int) -> dif.ClientMetadata:
    match id:
        case 1:
            client_name = "Dummy University"
            logo_uri = "Dummy Logo Uri"
        case 2:
            client_name = "Dummy ELFA"
            logo_uri = "Dummy Logo Uri"
        case _:
            raise ex.PresentationDefinitionNotFoundError()

    return dif.ClientMetadata(client_name=client_name, logo_uri=logo_uri)
