# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
import httpx
import logging

from wallet import config as conf

# API KEY TODO: Different API Keys for different servers
api_key = os.getenv("API_KEY", "tergum_dev_key")
import common.model.dif_presentation_exchange as models


def request_request_object(
    auth_request_uri: str,
    config: conf.WalletConfig,
) -> models.RequestObject:
    r = httpx.get(auth_request_uri, verify=config.enable_ssl_verification)
    # assert r.status_code == 200, f"Request Object answer must be successful {r.text}"
    return models.RequestObject.model_validate_json(r.content)


def send_presentation(
    auth_request_uri: str,
    presentation_submission: models.DIFPresentationSubmission,
    vp_token: str,
    config: conf.WalletConfig,
) -> tuple[int, str]:
    """
    Sends the presentation, returns the status code returned by the verifier
    Returns the status code & unparsed text of the response.
    """
    # Get the request-object from the verifier to know where the submission has to be sent to
    response_auth_request = httpx.get(auth_request_uri, verify=config.enable_ssl_verification)
    request_object = models.RequestObject.model_validate_json(response_auth_request.content)

    # Request parameter are based on https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-6.2 "direct_post" method
    r = httpx.post(
        request_object.response_uri,
        headers={'accept': 'application/x-www-form-urlencoded', 'Content-Type': 'application/x-www-form-urlencoded'},
        data={"presentation_submission": presentation_submission.model_dump_json(exclude_none=True), "vp_token": vp_token},
        verify=config.enable_ssl_verification,
    )
    if r.status_code != 200:
        logging.info(f"{r.text=}")
    return r.status_code, r.text
