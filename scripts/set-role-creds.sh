#!/bin/bash

if [ ! -e "$(pwd)/_output/state.json" ]; then
    echo "State file with Role ARN file not found.  Run 'sts-preflight create' first"
    return
fi

if [ ! -e "$(pwd)/_output/token" ]; then
    echo "Token file not found.  Run 'sts-preflight token' first"
    return
fi

for i in $(export | grep AWS | cut -f3 -d' ' | cut -f1 -d'='); do unset $i; done

export AWS_ROLE_ARN="$(jq -r .roleARN _output/state.json)"
export AWS_WEB_IDENTITY_TOKEN_FILE="$(pwd)/_output/token"
echo "AWS_ROLE_ARN and AWS_WEB_IDENTITY_TOKEN_FILE environment variables set"