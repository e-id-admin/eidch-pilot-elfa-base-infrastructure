<!--
SPDX-FileCopyrightText: 2024 Swiss Confederation

SPDX-License-Identifier: MIT
-->

# Changelog

## 4.1.0
- Add ability to verifier to check for preselected issuers.

## 4.0.0
- Verifier data can only be fetched one time.
- Handle public key requests better.

## 3.4.0
- The alembic logging is configured for splunk
- Log points for verification are available

## 3.3.0
- Nonce logic in verfication.py updated (must be the same as in request object)

## 3.2.0
- Add client metadata to verification request
- 
## 3.1.0
- Rename AuthorizationResponseData error_detail_code to error_code
- Rename in Error Response error_detail_code to error_code 

## 3.0.0
 - Streamline health endpoints (added /health/, /health/liveness, /health/readiness, removed /health, /liveness, /readiness )
 
## 2.0.1
- Introduce expire attributes for verification related models. The ttl is set by using the VERIFICATION_TTL env variable

## 2.0.0
-  Convert logging format to json to be aligned with requirements of splunk

## 1.0.0
-  Modified to use common module from package