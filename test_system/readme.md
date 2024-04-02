<!--
SPDX-FileCopyrightText: 2024 Swiss Confederation

SPDX-License-Identifier: MIT
-->

# Happy Path Flow core components
## Issuance
```mermaid
sequenceDiagram
    participant TestRunner
    participant Issuer
    participant Wallet
    TestRunner->>Issuer: set metadata
    TestRunner->>Issuer: Create Offer with subject data
    Issuer->>TestRunner: managment_id & offer
    TestRunner->>Wallet: offer deeplink
    Wallet->>Issuer: issuer metadata
    Issuer->>Wallet: issuer metadata
    Wallet->>Issuer: Redeem one-time-login uuid
    Issuer->>Wallet: BEARER Token
    Wallet->>Issuer: Get VC with Holder binding
    Issuer->>Wallet: Signed VC
    Wallet->>TestRunner: Success
```
## Verification
```mermaid
sequenceDiagram
    participant TestRunner
    participant Wallet
    participant Verifier
    TestRunner->>Verifier: Create Verification Request with DIF PE
    Verifier->>TestRunner: management_id & offer_uri
    TestRunner->>Wallet: offer_uri
    Wallet->>Verifier: Request Request Object
    Verifier->>Wallet: Request Object
    Wallet->>Verifier: VP-Token
    Verifier->>Base Registry: Get Issuer Public Key
    Verifier->>Revocation Registry: Get Status List
    Verifier->>Verifier: Check VP & VC
    Verifier->>Wallet: Success
    Wallet->>TestRunner: Success
```

# Failures tested
## Issuance
For issuance there the only errors that should occure when users are invovled are; the offer is expired or already used.

There are plenty of possible errors in the redeeming process, but these stem from an implementation error on the wallet side.

### Expired Offer `test_expired_offer`
Offer attempting to redeem is expired

```mermaid
sequenceDiagram
    participant TestRunner
    participant Issuer
    participant Wallet
    TestRunner->>Issuer: Create Offer with subject data and offer validity of 0 seconds
    Issuer->>TestRunner: managment_id & offer
    TestRunner->>Wallet: offer deeplink
    Wallet->>Issuer: issuer metadata
    Issuer->>Wallet: issuer metadata
    Wallet->>Issuer: Redeem one-time-login uuid
    Issuer->>Wallet: Error - Invalid (expired) one-time-login
    Wallet->>TestRunner: Failure & Error Details
```

### Used Offer `test_used_offer`
Offer has already been redeemed once before
```mermaid
sequenceDiagram
    participant TestRunner
    participant Issuer
    participant Wallet
    TestRunner->>Issuer: Create Offer with subject data
    Issuer->>TestRunner: managment_id & offer
    TestRunner->>Wallet: offer deeplink
    Wallet->>Issuer: issuer metadata
    Issuer->>Wallet: issuer metadata
    Wallet->>Issuer: Redeem one-time-login uuid
    Issuer->>Wallet: BEARER Token
    Wallet->>Issuer: Get VC with Holder binding
    Issuer->>Wallet: Signed VC
    Wallet->>TestRunner: Success
    TestRunner->>Wallet: same offer deeplink again
    Wallet->>Issuer: issuer metadata
    Issuer->>Wallet: issuer metadata
    Wallet->>Issuer: Redeem one-time-login uuid
    Issuer->>Wallet: Error - Invalid (already used) one-time-login
    Wallet->>TestRunner: Failure & Error Details
```

## Verification
### Expired VC `test_expired_vc`
Issuance of expired VC
Attempt to verify it

```mermaid
sequenceDiagram
    participant TestRunner
    participant Wallet
    participant Verifier
    TestRunner->>Verifier: Create Verification Request with DIF PE
    Verifier->>TestRunner: management_id & offer_uri
    TestRunner->>Wallet: offer_uri
    Wallet->>Verifier: Request Request Object
    Verifier->>Wallet: Request Object
    Wallet->>Verifier: VP-Token
    Verifier->>Base Registry: Get Issuer Public Key
    Verifier->>Revocation Registry: Get Status List
    Verifier->>Verifier: Check VP & VC
    Verifier->>Wallet: Failure
    Wallet->>TestRunner: Failure & error details
    TestRunner->>Verifier: Get Verification Status
    Verifier->>TestRunner: Failure & error details
```

### Suspended / Revoked VC `test_vc_states`
VC which is suspended / revoked

```mermaid
sequenceDiagram
    participant TestRunner
    participant Issuer
    participant Wallet
    participant Verifier
    TestRunner->>Issuer: Set VC Status
    Issuer->>Revocation Registry: Update Status List
    TestRunner->>Verifier: Create Verification Request with DIF PE
    Verifier->>TestRunner: management_id & offer_uri
    TestRunner->>Wallet: offer_uri
    Wallet->>Verifier: Request Request Object
    Verifier->>Wallet: Request Object
    Wallet->>Verifier: VP-Token
    Verifier->>Base Registry: Get Issuer Public Key
    Verifier->>Revocation Registry: Get Status List
    Verifier->>Verifier: Check VP & VC
    Verifier->>Wallet: Failure
    Wallet->>TestRunner: Failure & error details
    TestRunner->>Verifier: Get Verification Status
    Verifier->>TestRunner: Failure & error details
```
