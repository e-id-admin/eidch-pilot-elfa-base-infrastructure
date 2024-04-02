# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Endpoints for jinja2 templates
"""

import fastapi
import jinja2
import logging

import common.db.postgres as db
import common.parsing as parsing
import issuer.config as conf
import issuer.db.credential as db_credential
import issuer.credential_offer as offer


TAG = "Deeplink Redirector"

router = fastapi.APIRouter(prefix="", tags=[TAG])


@router.get("/offer/{offer_id_b64}", description="Serverside renders a HTML page with the full offer link")
def render_deeplink_page(
    request: fastapi.Request,
    offer_id_b64: str,
    config: conf.inject,
    session: db.inject,
):
    try:
        offer_id = parsing.uuid_from_url_safe(offer_id_b64)
        credential_offer = db_credential.get_offer(session, offer_id)
        if not credential_offer:
            raise ValueError()
        offer_link = offer.create_preauthorized_offer_link(
            metadata_credential_supported_ids=[credential_offer.metadata_credential_supported_id],
            pre_auth_code=str(credential_offer.id),
            external_url=config.external_url,
            pin_required=bool(credential_offer.pin),
        )
        return config.get_template_resource().TemplateResponse(
            config.redirect_template_shortlink,
            {
                "request": request,
                "offer_link": offer_link,
            },
        )

    except ValueError:
        raise fastapi.HTTPException(status_code=404)
    except jinja2.TemplateNotFound:
        logging.exception(f"Redirect Template not found: {config.template_directory}/{config.redirect_template_shortlink}")
        raise fastapi.HTTPException(
            status_code=500,
            detail="Server Configuration Error: Redirect Template not found.",
        )


@router.get("/get-wallet", description="Delivers a HTML page for redirecting to the correct app")
def render_appstore_redirect_page(
    request: fastapi.Request,
    config: conf.inject,
):
    return config.get_template_resource().TemplateResponse(
        config.redirect_template_store,
        {"request": request},
    )
