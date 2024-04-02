# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

import os
import json
import logging
from typing import Annotated
from functools import cache

import httpx

from fastapi import Depends, templating

import common.config as conf
from issuer import models


def _create_api_key_header(api_key: str) -> dict:
    return {"x-api-key": api_key}


class IssuerConfig(conf.Config):
    def __init__(self):
        super().__init__()
        self.app_name = os.getenv("APP_NAME", "Issuer Agent")
        self.issuer_id = os.getenv("ISSUER_ID")

        # Registry API Keys
        self.registry_key_api_key = os.getenv("REGISTRY_BASE_API_KEY")
        """Key to update published data on the base registry"""
        self.registry_revocation_api_key = os.getenv("REGISTRY_REVOCATION_API_KEY")
        """Key to update status lists on the revocation registry"""

        # Status List
        raw_statuslist_config = json.loads(os.getenv("STATUS_LIST_CONFIG", "[]"))
        if raw_statuslist_config:
            self.load_status_list_config(raw_statuslist_config)
        else:
            logging.error("No status lists configured! Requires environment variables STATUS_LIST_CONFIG to be set to function correctly")

        # Templates
        self.template_directory = os.getenv("TEMPLATE_BASE_DIR", "issuer/tmp/res/template")
        """Base directory for jinja"""
        self.redirect_template_shortlink = os.getenv("TEMPLATE_REDIRECT_OFFER", "offer_link_redirect.html")
        """Template for the short url redirect page"""
        self.redirect_template_store = os.getenv("TEMPLATE_REDIRECT_STORE", "store_redirect.html")
        """Template for the app store redirect page"""

    def load_status_list_config(self, raw_statuslist_config: str):
        self.status_list_config: list[models.StatusListConfiguration] = list(map(models.StatusListConfiguration.model_validate, raw_statuslist_config))
        self.status_list_map = dict(map(lambda sl_conf: (sl_conf.purpose, sl_conf.status_list_id), self.status_list_config))
        """Map from purpose to currently used status list id"""

    def get_status_list_purposes(self) -> set[str]:
        return set(self.status_list_map.keys())

    def get_status_list_uri(self, purpose: str):
        """
        Gets the statuslist for the given purpose
        throws a KeyError if the purpose is not found
        """
        return f'{self.registry_revocation_url}/issuer/{self.issuer_id}/status-list/{self.status_list_map[purpose]}'

    def get_key_registry_uri(self):
        """Reference to the registry entry where issuer data can be fetched
        example {get_key_registry_uri}/.well-known/jwks.json
        """
        return f'{self.registry_key_url}/issuer/{self.issuer_id}'

    @cache
    def get_template_resource(self) -> templating.Jinja2Templates:
        return templating.Jinja2Templates(self.template_directory)

    @cache
    def get_revocation_registry_client(self) -> httpx.Client:
        """Create a httpx client capable of interacting with revocation registry"""
        return httpx.Client(
            verify=self.enable_ssl_verification,
            headers=_create_api_key_header(self.registry_revocation_api_key),
        )

    @cache
    def get_base_registry_client(self) -> httpx.Client:
        """Create a httpx client capable of interacting with base registry"""
        return httpx.Client(
            verify=self.enable_ssl_verification,
            headers=_create_api_key_header(self.registry_key_api_key),
        )


inject = Annotated[IssuerConfig, Depends(IssuerConfig)]
