# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

# Sets HSM environment variables for tests
export SOFTHSM2_CONF=$(pwd)/softhsm2.conf
export HSM_LIBRARY=$(pwd)/libsofthsm2.so
export HSM_TOKEN=dev-token
export HSM_PIN=1234
export HSM_LABEL=dev-issuer
export HSM_SIGNING_ALGORITHM=ES512