# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

# Name (& directory) of the service
ARG component
# Dependency groups used by the service
ARG poetry_dependency_groups
# Indication if SoftHSM should be installed. If set softhsm will be installed
ARG install_softhsm

FROM python:3.11-alpine as build

ARG component
ARG poetry_dependency_groups

# Install packages required for DB access & GIT installing SD-JWT reference implementation
RUN apk add build-base git libpq-dev

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

# Prepare Pip
RUN pip install --upgrade pip setuptools --no-cache-dir
RUN pip install poetry --no-cache-dir
# Copy Dependencies
COPY ./poetry.lock .
COPY ./pyproject.toml .
# Set up Common
RUN mkdir -p ./common/common/
# Ensure common is a package
RUN touch ./common/common/__init__.py
COPY ./common/*.toml common/
# venv
RUN python -m venv /app/.venv
RUN poetry install --no-root --only ${poetry_dependency_groups}
# uninstall unused dependencies
RUN /app/.venv/bin/pip uninstall -y pip setuptools

FROM python:3.11-alpine as run

ARG component
ARG COMMIT_HASH
ARG COMMIT_TIMESTAMP
ARG VERSION
ARG install_softhsm

# uninstall unused dependencies
RUN pip uninstall -y pip setuptools

# install nessecary runtime dependencies
# libpq-dev => DB access
RUN apk add libpq-dev=16.2-r1

# Install packages required for hsm access
RUN apk add libstdc++ gcompat opensc

# Upgrade - There are not allways the most recent packages installed
RUN apk upgrade

# SOFTHSM install if install_softhsm is set
RUN if [[ -n "${install_softhsm}" ]] ; then apk add softhsm ; fi


WORKDIR /app

COPY --from=build /app/.venv /app/.venv


ENV COMMIT_HASH=$COMMIT_HASH
ENV COMMIT_TIMESTAMP=$COMMIT_TIMESTAMP
ENV VERSION=$VERSION
ENV COMPONENT=$component

COPY ./${component}/ ${component}
COPY ./common/ common/
COPY ./${component}/main.py main.py
EXPOSE 8080/tcp

RUN addgroup -S APPGROUP && adduser -S APPUSER -G APPGROUP

USER APPUSER

ENTRYPOINT ["/app/.venv/bin/uvicorn", "main:app"]
CMD ["--host", "0.0.0.0", "--port", "8080", "--forwarded-allow-ips", "*"]
