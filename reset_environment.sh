#!/bin/bash

# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

# Commands to reset the environment, ignoring errors
rm -r .venv -f
rm -r cert -f
rm -r wallet_data/* -f
docker compose down -v --remove-orphans
rm .env -f