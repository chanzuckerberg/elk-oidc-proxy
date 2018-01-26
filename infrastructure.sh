#!/usr/bin/env bash

ACTION=$1

shift 1

terraform "$ACTION" \
  -var "aws_profile=${AWS_PROFILE}" \
  -var "aws_region=${AWS_DEFAULT_REGION}" \
  -var "cluster=${CLUSTER}" \
  -var "app_name=${APP_NAME}" \
  -var "domain_name=${DOMAIN_NAME}" \
  -var "proxy_fqdn=${PROXY_fqdn}" \
  -var "terraform_bucket=${TERRAFORM_BUCKET}" \
  $([[ "$ACTION" == "plan" ]] && echo -n "-detailed-exitcode" || echo -n "") \
  "$@"
