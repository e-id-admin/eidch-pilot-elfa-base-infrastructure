#!/bin/bash

# SPDX-FileCopyrightText: 2024 Swiss Confederation
#
# SPDX-License-Identifier: MIT

set -e
# Move to where the script is located
cd $(dirname $0)

# Credential Creation
MY_IP="157.143.5.86"
DIR=cert

# Dev Issuer Onboarding
ISSUER_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8000"
REGISTRY_BASE_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8010"
REGISTRY_REVOCATION_SERVICE_URL="https://${HOST_PREFIX:-localhost}:8011"
ADMIN_SERVICE_URL="https://${HOST_PREFIX:-localhost}:1337"
ADMIN_HEADER_API_KEY="x-api-key: tergum_dev_key"

create_dotenv() {
    echo "# .env managed by setup_environment.sh" > .env
    # Static .env settings
    # api keys
    echo "REGISTRY_REVOCATION_API_KEY=revocation_dev_key" >> .env
    echo "REGISTRY_BASE_API_KEY=base_dev_key" >> .env
}

load_env_file() {
    set -o allexport
    source .env 
    set +o allexport
}

install_venv() {
    if [ ! -d ".venv/" ]; then
        echo 'Create venv'
        python3 -m venv .venv 
        echo 'install dev dependencies'
        .venv/bin/pip install poetry
        .venv/bin/poetry install --no-root
    fi
}

install_other_dependencies() {
    if [[ ! "$(command -v softhsm2-util)" ]]
    then
        echo "Installing SoftHSM"
        sudo apt update
        # Includes pkcs11-tool, which is used to generate the keys
        sudo apt install opensc -y
        # Software Hardware Security Module to emulate hsm access
        sudo apt install softhsm2 -y
    fi
}

set_log_level() {
    LOG_LEVEL="INFO"
    echo "LOG_LEVEL=$LOG_LEVEL" >> .env
}

set_debug_mode() {
    echo "ENABLE_DEBUG_MODE=True" >> .env
}

generate_local_dev_certs() {
    echo "######################################"
    echo "Generating certs for $1"
    echo "######################################"
    WORKDIR=$DIR/$1
    mkdir $WORKDIR
    # RSA
    openssl req -x509 -newkey rsa:4096 -keyout $WORKDIR/rsa_private.pem -out $WORKDIR/rsa_public.pem -sha256 -days 3650 -nodes -subj "/CN=localhost" -addext "subjectAltName=IP:127.0.0.1,IP:$MY_IP"
    # Elliptic Curve
    # sect571r1 : NIST/SECG curve over a 571 bit binary field
    openssl ecparam -genkey -name secp521r1 -out $WORKDIR/ec_private.pem
    openssl ec -in $WORKDIR/ec_private.pem -pubout -out $WORKDIR/ec_public.pem
}


generate_all_certs() {
    if [ ! -d "$DIR/" ]; then
        mkdir $DIR   
        for d in admin issuer verifier registry_base registry_revocation wallet
        do
            generate_local_dev_certs $d    
        done
    else
        echo "Certificates already present."
    fi

    echo "######################################"
    echo "All Done. Enjoy your certs!"
}

generate_hsm_certs() {
    echo "Generating a softhsm cert for the issuer"
    # Note: This requires the path in softhsm2.conf to be correct and the path to softhsm2.conf to be set
    # export SOFTHSM2_CONF=$(pwd)/softhsm2.conf
    if [[ -z "${SOFTHSM2_CONF}" ]]; then
        source hsm_environment_variables.sh
    fi
    echo "Using SOFTHSM2_CONF at $SOFTHSM2_CONF"
    # Copy shared objects library to project dir
    SOFTHSM_LOCATION=$(dpkg --search libsofthsm2.so | head -n 1 | cut -d " " -f 2)
    cp $SOFTHSM_LOCATION .
    # Write env variables
    echo "HSM_LIBRARY=$HSM_LIBRARY" >> .env
    echo "HSM_TOKEN=$HSM_TOKEN" >> .env
    echo "HSM_PIN=$HSM_PIN" >> .env
    echo "HSM_LABEL=$HSM_LABEL" >> .env
    echo "HSM_SIGNING_ALGORITHM=$HSM_SIGNING_ALGORITHM" >> .env
    if [ ! -d "$DIR/hsm" ]; then
        # Setup SoftHSM if not already set up
        mkdir $DIR/hsm
        # Initialize the slot
        softhsm2-util --init-token --slot 0 --label $HSM_TOKEN --pin $HSM_PIN --so-pin 4321
        #Generate the EC key
        pkcs11-tool --module=$SOFTHSM_LOCATION --token-label $HSM_TOKEN --pin $HSM_PIN --keypairgen --mechanism ECDSA-KEY-PAIR-GEN --key-type EC:secp521r1 --usage-sign --label $HSM_LABEL
        # Extract the public key
        pkcs11-tool --module=$SOFTHSM_LOCATION --token-label $HSM_TOKEN --label $HSM_LABEL --read-object --type pubkey -o $DIR/issuer/hsm_ec521_pub.key
        # Convert the public key for the issuer
        # Note: This is only necessary for this script. 
        # The issuer extracts the public key itself from the HSM
        openssl ec -pubin -inform DER -in $DIR/issuer/hsm_ec521_pub.key -outform PEM -out $DIR/issuer/hsm_ec521_pub.pem
    fi
}

workaround_ci_permissions() {
    if [ ! -d "$DIR/issuer/hsm" ]; then
        chmod -R 777 ./cert # container user uid may not be the same as user id which then results in permission issues in the CI tests
    fi
}

wait_for_liveness() {
    SERVICE_URL=$1
    # Calls liveness check, needs ||: (or True) so the script does not terminate on ssl handshake error
    LIVENESS_STATUS=$(curl $SERVICE_URL/health/liveness -k -s -o /dev/null -w "%{response_code}")||:
    # Returns 000 if no connection
    RETRY_COUNTER=0 # Prevent infinite wait
    while test $LIVENESS_STATUS = "000" && test $RETRY_COUNTER -lt 30
    do
        echo -n .
        sleep 1
        LIVENESS_STATUS=$(curl $SERVICE_URL/health/liveness -k -s -o /dev/null -w "%{response_code}")||:
        RETRY_COUNTER=$(( RETRY_COUNTER + 1 ))
    done

}

start_admin_containers() {
    mkdir -p wallet_data
    #####
    # Starting Base Registry Containers
    echo "UID=$(id -u)" >> .env
    echo "GID=$(id -g)" >> .env
    echo "Starting Base Registry Services"
    docker compose up -d admin db_base db_revocation registry_base registry_revocation
    echo "Waiting for startup to be complete"
    wait_for_liveness $REGISTRY_BASE_SERVICE_URL
    wait_for_liveness $REGISTRY_REVOCATION_SERVICE_URL
    echo "Done waiting. Ready or not here I come!"
}

create_status_list_config() {
    # Creates a status list and returns the id
    ISSUER_ID=$1
    PURPOSE=$2

    STATUS_LIST_REGISTRATION=$(curl -X PUT $ADMIN_SERVICE_URL/issuer/$ISSUER_ID/status-list -k -H "$ADMIN_HEADER_API_KEY")
    STATUS_LIST_ID=$(echo $STATUS_LIST_REGISTRATION | jq -r '.id')
    echo "{\"status_list_id\": \"$STATUS_LIST_ID\", \"purpose\": \"$PURPOSE\"}"
}


onboard_dev_issuer() {
    # Onboarding Process
    # Represents the Registry Admin onboarding a new issuer
    B64_PK=$(base64 -w 0 $DIR/issuer/ec_public.pem)
    B64_HSM_PK=$(base64 -w 0 $DIR/issuer/hsm_ec521_pub.pem)
    DATA="[{\"key_type\": \"EC\", \"base64_encoded_key\": \"$B64_PK\"},{\"key_type\": \"EC\", \"base64_encoded_key\": \"$B64_HSM_PK\"}]"
    echo "Registering Public Key at Registry"
    REGISTRATION=$(curl -X PUT $ADMIN_SERVICE_URL/issuer -k -H "$ADMIN_HEADER_API_KEY" -H "Content-Type: application/json" -d "$DATA")
    ISSUER_ID=$(echo $REGISTRATION | jq -r '.id')   
    echo "New Issuer ID is $ISSUER_ID"
    echo "Creating Status Lists"
    REVOCATION_STATUS_LIST_CONFIG=$(create_status_list_config $ISSUER_ID revocation)
    SUSPENSION_STATUS_LIST_CONFIG=$(create_status_list_config $ISSUER_ID suspension)

    export ISSUER_ID=$ISSUER_ID
    export STATUS_LIST_CONFIG="[$REVOCATION_STATUS_LIST_CONFIG, $SUSPENSION_STATUS_LIST_CONFIG]"
    echo "ISSUER_ID=$ISSUER_ID" >> .env
    echo "STATUS_LIST_CONFIG=$STATUS_LIST_CONFIG" >> .env
}


configure_systems() {
    # Configures the Issuer System
    # This step represents the issuer configuring his system with the status 
    # list information provided by the onboarding process
    echo "Start systems to configure issuer..."
    docker compose up -d 
    wait_for_liveness $ISSUER_SERVICE_URL
    echo "Configure wallet for container use ..."
    chmod -R 777 "./wallet_data" # container user uid may not be the same as user id which then results in permission issues in the CI tests
    echo "done"

    # Set issuer status list
    echo "Configure status list of issuer..."
    CONFIG_RESULT=$(curl -X PATCH $ISSUER_SERVICE_URL/admin/status-list -k -H "$ADMIN_HEADER_API_KEY")
    if [[ "$CONFIG_RESULT" != "null" ]]; then
        echo "ERROR: Could not create Status List! $CONFIG_RESULT"
        exit 1
    fi

    # Set issuer metadata
    echo "Configure issuer metadata..."
    CONFIG_RESULT=$(curl -X POST $ISSUER_SERVICE_URL/oid4vc/admin/metadata -k -H "$ADMIN_HEADER_API_KEY" -H "Content-Type: application/json" -d @test_system/files/issuer_metadata.json)
    if [[ "$CONFIG_RESULT" != "null" ]]; then
        echo "ERROR: Could not create Status List! $CONFIG_RESULT"
        exit 1
    fi
    echo "done"
}

bulid_images() {
    echo "Build docker images"
    docker compose build
    echo "done"
}

configure_pytest() {
    echo "[pytest]" > pytest.ini
    echo "env = " >> pytest.ini
    echo "    SOFTHSM2_CONF=$SOFTHSM2_CONF" >> pytest.ini
    echo "    HSM_LIBRARY=$HSM_LIBRARY" >> pytest.ini
    echo "    HSM_TOKEN=$HSM_TOKEN" >> pytest.ini
    echo "    HSM_PIN=$HSM_PIN" >> pytest.ini
    echo "    HSM_LABEL=$HSM_LABEL" >> pytest.ini
    echo "    HSM_SIGNING_ALGORITHM=$HSM_SIGNING_ALGORITHM" >> pytest.ini
    echo "    ISSUER_ID=$ISSUER_ID" >> pytest.ini
    # echo "    STATUS_LIST_CONFIG=$STATUS_LIST_CONFIG" >> pytest.ini
    # pytest-env doesn't load inis correctly and can not load a string looking like a json
    echo "    STATUS_LIST_CONFIG=[]" >> pytest.ini
    echo "    ENABLE_DEBUG_MODE=True" >> pytest.ini
}

echo "###########################"
echo "Setting environment to dev"
create_dotenv
set_log_level
set_debug_mode
load_env_file
echo "###########################"
echo "Installing python venv"
install_venv
install_other_dependencies
echo "###########################"
echo "Generating Key Material"
generate_all_certs
generate_hsm_certs
workaround_ci_permissions  
echo "###########################"
echo "Building Container Images"
bulid_images
echo "###########################"
echo "Starting Admin Containers"
start_admin_containers
echo "###########################"
echo "Onboarding the dev issuer"
onboard_dev_issuer
echo "###########################"
echo "Configuring Issuer"
configure_systems
echo "###########################"
echo "Creating pytest.ini"
configure_pytest
echo "###########################"
echo "All Done!"
