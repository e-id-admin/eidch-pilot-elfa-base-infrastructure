# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

# If we're in the issuer directory, we need to add the root module so the 
# imports will be the same as in the docker
import sys, os
sys.path.insert(0, os.getcwd())

import uvicorn

from wallet.wallet import app

if __name__ == '__main__':
    # HTTP
    uvicorn.run("wallet.wallet:app", host="0.0.0.0", port=8000, reload=True)
    # HTTPS
    # uvicorn.run("issuer.issuer:app", host="0.0.0.0", port=8000, reload=True, ssl_keyfile="cert/private.pem", ssl_certfile="cert/public.pem") 