# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

"""
Provides general Environment Variables for FastAPI dependcy injection
"""

import os
from typing import Annotated

from fastapi import Depends

from common.parsing import interpret_as_bool


class Config:
    def __init__(self):
        self.enable_debug_mode: bool = interpret_as_bool(os.environ.get("ENABLE_DEBUG_MODE", "False"))
        '''General debug mode configuration enabler.'''

        self.external_url = os.getenv("EXTERNAL_URL")
        # TODO -> EID-1162: Rename Environment Variable
        self.registry_key_url = os.getenv("REGISTRY_BASE_URL")
        self.registry_revocation_url = os.getenv("REGISTRY_REVOCATION_URL")
        self.api_key = os.getenv("API_KEY", "tergum_dev_key")
        '''Apikey to use for the application. Default: "tergum_dev_key".'''

        self.db_connection = os.getenv("DB_CONNECTION")
        self.singing_key_public = os.getenv("SIGNING_KEY_PUBLIC")
        self.singing_key_public = os.getenv("SIGNING_KEY_PRIVATE")
        self.enable_ssl_verification: bool = interpret_as_bool(os.environ.get("ENABLE_SSL_VERIFICATION", not self.enable_debug_mode))
        '''
        Enable ssl verification for outgoing requests.
        Default is True, but False in DEBUG_MODE.
        '''
        self.app_name = os.getenv("APP_NAME", "anonymous")
        '''
        Human readable application name used for loggin
        '''
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.enable_documentation_endpoints: bool = interpret_as_bool(os.environ.get("ENABLE_DOCUMENTATION_ENDPOINTS", self.enable_debug_mode))
        '''
        Enable /doc and /redoc endpoint.
        Default is False, but True in DEBUG_MODE.
        '''
        self.enable_cors: bool = interpret_as_bool(os.environ.get("ENABLE_CORS", self.enable_debug_mode))
        '''
        Enable CORs for incomming openapi requests
        Default is False, but True in DEBUG_MODE.
        '''
        self.additional_allowed_origins = os.environ.get('ADDITIONAL_ALLOWED_ORIGINS', '')
        '''
        If CORs is enabled additional allowed origins e.g confluence can be defined as comma separated list of url (e.g. URL,URL,URL)
        '''
        self.enable_splunk_log: bool = interpret_as_bool(os.environ.get("ENABLE_SPLUNK_LOG", not self.enable_debug_mode))
        '''
        Enable Splunk compatible log format.
        Default is False, but True in DEBUG_MODE.
        '''


inject = Annotated[Config, Depends(Config)]


class DBConfig:
    def __init__(self):
        self.SQLALCHEMY_DATABASE_URL = os.getenv("DB_CONNECTION", "postgresql://reg:supersecret@db_base/registry")
        self.SQLALCHEMY_DATABASE_SCHEMA = os.getenv("DB_SCHEMA", "openid4vc")
        component = os.getenv("COMPONENT")
        """issuer / base_registry / ..."""
        self.ALEMBIC_CONFIG_FILE = f"{component}/alembic.ini"


inject_db_config = Annotated[DBConfig, Depends(DBConfig)]
