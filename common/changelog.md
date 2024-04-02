<!--
SPDX-FileCopyrightText: 2024 Swiss Confederation

SPDX-License-Identifier: MIT
-->

# Changelog

## 3.2.0
- Add wrapper for handling failing http get calls

## 3.1.1
- Improve Error handling in communication with registries
- JWT handling crashes with more sensible errors

## 3.1.0
- Splunk logging is now conform to the requirements set by splunk and raeda
- The alembic logging now does not overwrite our own logging
- logging_config.py has been split for easier readability
  
## 3.0.0
- Update Verifiable Credential Metadata to use credential_supported as dictionary (OID4VC 12)
- move /health endpoint to /health/debug

## 2.2.0
 - add health endpoint option

## 2.1.2
- Add ADDITIONAL_ALLOWED_ORIGINS env variable to allow white listing e.g. confluence -> issuing page

## 2.1.1
- Add USE_HTTPS env variable in base registry

## 2.1.0
- Adding Fastapi application wrapper for used project patterns
- Fix exception logging in splunk logs
- create a feature flag for splunk logs

## 2.0.0
-  Convert logging format to json to be aligned with requirements of splunk
  
## 1.0.1
- Add dependencies of the common project to the package

## 1.0.0
- initial packaging of common module
- Including test_helpers from test_system module