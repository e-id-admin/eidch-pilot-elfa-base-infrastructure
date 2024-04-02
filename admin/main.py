# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

from admin.admin import app

if __name__ == '__main__':
    import uvicorn

    # HTTP
    # uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
    # HTTPS
    uvicorn.run(app, host="0.0.0.0", port=443, reload=True, ssl_keyfile="cert/private.pem", ssl_certfile="cert/public.pem")
