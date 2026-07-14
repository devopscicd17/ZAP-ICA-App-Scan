#!/bin/false
# shellcheck shell=bash
# shebang to indicate if can only be invoked using source . command

# Set filter options to Low to prevent a false positive by zap-ui
# https://ibm-cloudplatform.slack.com/archives/C010DQ17EPJ/p1707120778488449
export filter_options="${filter_options:-Low,Informational}"

# Configure the API_DATA_FILE
if [[ -n "${API_DATA_FILE:-}" ]] && [[ -f "${API_DATA_FILE}" ]]; then
    TMP_API_DATA_FILE=$(mktemp)

    # TODO: replace with "apisToScan": ["all"],
    jq '.apisToScan += [{"path":"/health", "method":"get"}]' \
      "${API_DATA_FILE}" > "${TMP_API_DATA_FILE}"

    cp -f "${TMP_API_DATA_FILE}" "${API_DATA_FILE}"
fi
