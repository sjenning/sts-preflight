#!/bin/bash

if [ ! -e "$(pwd)/_output/role-arn" ]; then
    echo "Role ARN file not found.  Run 'sts-preflight create' first"
    return
fi

if [ ! -e "$(pwd)/_output/token" ]; then
    echo "Token file not found.  Run 'sts-preflight token' first"
    return
fi

for i in $(export | grep AWS | cut -f3 -d' ' | cut -f1 -d'='); do unset $i; done

set -x
export AWS_ROLE_ARN=$(cat $(pwd)/_output/role-arn)
export AWS_WEB_IDENTITY_TOKEN_FILE=$(pwd)/_output/token
set +x