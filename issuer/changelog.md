<!--
SPDX-FileCopyrightText: 2024 Swiss Confederation

SPDX-License-Identifier: MIT
-->

# Changelog

## 4.1.0
- The alembic logging is configured for splunk
- Log points for issuance are available
- 
## 4.0.0
- Update Issuer Metadata to use credentials_supported as dictionary (oid4vci v12)

## 3.1.0
 - move status list check from /health/readiness to /health/liveness

## 3.0.0
 - Streamline health endpoints (added /health/, /health/liveness, /health/readiness, removed /admin/health )

## 2.0.1
-  Cleanup of expired offers running on startup and every midnight

## 2.0.0
-  Convert logging format to json to be aligned with requirements of splunk

## 1.1.0
-  New endpoint allowing to create a shortened link for an offer using the management id 
-  Endpoint to get the deeplink from the short link
-  Mountable template for the short link  (for redirect)

## 1.0.0
-  Modified to use common module from package
