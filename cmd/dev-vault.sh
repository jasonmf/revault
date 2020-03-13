#!/bin/bash

VAULT_BIN=/tmp/vault
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=abcdef
SEC_MOUNT="/devsecrets"
SEC_PATH="${SEC_MOUNT}/foo"
SEC_NAME="blarg"
SEC_VALUE="somesec"

(
	sleep 2
	${VAULT_BIN} secrets enable -version=2 -path=${SEC_MOUNT} kv
	${VAULT_BIN} kv put ${SEC_PATH} ${SEC_NAME}=${SEC_VALUE}
) &

${VAULT_BIN} server -dev -dev-root-token-id=${VAULT_TOKEN}
