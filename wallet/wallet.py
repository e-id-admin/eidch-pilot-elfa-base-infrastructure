# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
import json
from typing import Annotated

from fastapi import Request, Form, Response
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from asgi_correlation_id import CorrelationIdMiddleware

import common.key_configuration as key
import common.verifiable_credential as vc
import common.model.dif_presentation_exchange as dif
from common.fastapi_extensions import ExtendedFastAPI
from common.health import HealthAPIRouter

import wallet.oid4vc_fetcher as fetcher
import wallet.opid4vp_presenter as presenter
import wallet.credential_store as store
from wallet import config as conf

app = ExtendedFastAPI(conf.inject)

app.add_middleware(CorrelationIdMiddleware)


TEMPLATE_DIR = "wallet/template"
templates = Jinja2Templates(directory=TEMPLATE_DIR)


@app.get("/", response_class=HTMLResponse)
def user_overview(request: Request):
    walt_id_users = [user for user in os.listdir(store.DATA_DIR)]
    return templates.TemplateResponse("users.html", {"request": request, "users": walt_id_users})
    # return walt_id_users


@app.post("/")
def add_user(request: Request, user_name: Annotated[str, Form()]):
    os.makedirs(os.path.join(store.DATA_DIR, user_name), exist_ok=True)
    return user_overview(request)


@app.get("/data/{user_name}", response_class=HTMLResponse)
def list_creds(request: Request, user_name: str):
    creds = store.get_all_user_credentials_json(user_name).values()
    jwts = [cred for cred in creds if type(cred) is dict]
    sd_jwts = [cred for cred in creds if type(cred) is list]
    return templates.TemplateResponse("credentials.html", {"request": request, "user_name": user_name, "jwt_creds": jwts, "sd_jwt_creds": sd_jwts})


@app.post("/data/{user_name}")
def add_credential_with_deeplink(
    request: Request,
    user_name: str,
    deeplink: Annotated[str, Form()],
    key_conf: key.inject,
    config: conf.inject,
):
    oid_credential = fetcher.fetch_openid4vci_credential(deeplink, key_conf, config)
    store.save_credential(user_name, oid_credential)
    return list_creds(request, user_name)


@app.get("/data/{user_name}/json")
def get_creds_json_data(request: Request, user_name: str) -> list:
    creds = list(store.get_all_user_credentials_json(user_name).values())
    return creds


@app.get("/data/{user_name}/jwt")
def get_creds_jwt_data(request: Request, user_name: str) -> list:
    creds = list(store.get_all_user_credentials_jwt(user_name).values())
    return creds


def process_verification_request(
    user_name: str,
    auth_request: Annotated[str, Form()],
    key_conf: key.KeyConfiguration,
    config: conf.WalletConfig,
):
    """Request and process the request object for OpenID4VP Verification
    Return a dictionary with
    jwt_creds, sd_jwt_creds, verification_status, response_body, verifier_metadata
    """
    ro = presenter.request_request_object(auth_request, config)
    credential_types = []
    # Fetch Descriptors
    for descriptor in ro.presentation_definition.input_descriptors:
        for field in descriptor.constraints.fields:
            if "$.vc.type[*]" in field.path:
                credential_types.append(field.filter.pattern)
    # Get credential (and put it in the right shape)
    cred_raw, cred_json = store.get_first_user_credential_with_type(user_name, credential_types)
    credential_obj = vc.OpenID4VerifiableCredentialJWT.model_validate(cred_raw)

    vp = vc.VerifiablePresentation(verifiableCredential=[credential_obj.credential], type="VerifiablePresentation")  # The signed jwt
    # Create VP
    vp_token = key_conf.encode_jwt(
        vc.JsonWebTokenBodyVCData(
            iss=key_conf.jwk_did,
            jti=ro.nonce,
            nonce=ro.nonce,
            vp=vp,
        ).model_dump(exclude_none=True)
    )

    # Create Presentation
    presentation_submission = dif.DIFPresentationSubmission(
        id="Fake",
        definition_id="News",
        descriptor_map=[dif.DIFPresentationDescriptor(id="One", format="jwt_vp_json", path_nested=dif.DIFPathNested(path="$.vp.verifiableCredential[0]", format='jwt_vc'))],
    )

    # Send
    status, response_body = presenter.send_presentation(
        auth_request,
        presentation_submission,
        vp_token,
        config,
    )

    return {
        "jwt_creds": [cred_json] if type(cred_json) is dict else [],
        "sd_jwt_creds": [cred_json] if type(cred_json) is list else [],
        "verification_status": status,
        "response_body": response_body,
        "verifier_metadata": ro.client_metadata.model_dump(),
    }


@app.post("/data/{user_name}/verification_status")
def verification_status_response(
    user_name: str,
    auth_request: Annotated[str, Form()],
    key_conf: key.inject,
    config: conf.inject,
):
    """This is used only in the system tests"""
    verification_data = process_verification_request(user_name, auth_request, key_conf, config)
    status = verification_data["verification_status"]
    return Response(content=json.dumps(verification_data), status_code=status)


@app.post("/data/{user_name}/verification")
def verification_html_response(
    request: Request,
    user_name: str,
    auth_request: Annotated[str, Form()],
    key_conf: key.inject,
    config: conf.inject,
):
    verification_data = process_verification_request(user_name, auth_request, key_conf, config)

    return templates.TemplateResponse(
        "verification_status.html",
        {
            "request": request,
            "jwt_creds": verification_data["jwt_creds"],
            "sd_jwt_creds": verification_data["sd_jwt_creds"],
            "verification_status": verification_data["verification_status"],
        },
    )


@app.delete("/data/{user_name}")
def delete_user_data(user_name: str) -> None:
    """
    Deletes all the data for a given user. Use with caution
    """
    store.delete_all_credentials_from_user(user_name)


#############
#  Health   #
#############

app.include_router(HealthAPIRouter())

if __name__ == '__main__':
    import uvicorn

    # HTTP
    uvicorn.run("cred_explorer:app", host="0.0.0.0", port=9000, reload=True)
