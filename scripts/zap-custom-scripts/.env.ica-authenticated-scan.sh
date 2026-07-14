#!/bin/false
# shellcheck shell=bash
# Source this file from run-ica-authenticated-scan.sh

# Compatibility helpers
if ! command -v set_env >/dev/null 2>&1; then
set_env() {
  local key="$1"; local value="${2:-}"
  key="${key//-/_}"
  key=$(echo "$key" | tr '[:lower:]' '[:upper:]')
  export "${key}=${value}"
}
fi

if ! command -v get_env >/dev/null 2>&1; then
get_env() {
  local key="$1"; local default="${2:-}"
  key="${key//-/_}"
  key=$(echo "$key" | tr '[:lower:]' '[:upper:]')
  printenv "$key" 2>/dev/null || printf "%s" "$default"
}
fi

export API_DATA_FILE="${API_DATA_FILE:-}"

set_env IBM_SSO_LOGIN_URL "${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"
set_env ZAP_CONTEXT_NAME "${ZAP_CONTEXT_NAME:-ICA-App-Context}"
set_env ZAP_MAX_DEPTH "${ZAP_MAX_DEPTH:-5}"
set_env ZAP_THREAD_COUNT "${ZAP_THREAD_COUNT:-5}"
set_env ZAP_SCAN_TIMEOUT "${ZAP_SCAN_TIMEOUT:-60}"
set_env ZAP_ALERT_THRESHOLD "${ZAP_ALERT_THRESHOLD:-MEDIUM}"
set_env ZAP_REPORT_DIR "${ZAP_REPORT_DIR:-./zap-reports}"
set_env FILTER_OPTIONS "${FILTER_OPTIONS:-Low,Informational}"
set_env ZAP_EXCLUDE_URLS "${ZAP_EXCLUDE_URLS:-.*logout.*,.*signout.*,.*sign-out.*}"
set_env ZAP_LOGGED_IN_INDICATOR "${ZAP_LOGGED_IN_INDICATOR:-\\QLogout\\E|\\Qlogout\\E}"
set_env ZAP_LOGGED_OUT_INDICATOR "${ZAP_LOGGED_OUT_INDICATOR:-\\QLogin\\E|\\Qlogin\\E|\\Qw3id.sso.ibm.com\\E}"
set_env ZAP_SESSION_TIMEOUT "${ZAP_SESSION_TIMEOUT:-1800}"
set_env ZAP_REAUTHENTICATE_ON_TIMEOUT "${ZAP_REAUTHENTICATE_ON_TIMEOUT:-true}"
set_env ZAP_AJAX_SPIDER_ENABLED "${ZAP_AJAX_SPIDER_ENABLED:-false}"
set_env ZAP_AJAX_SPIDER_BROWSER "${ZAP_AJAX_SPIDER_BROWSER:-firefox}"
set_env ZAP_AJAX_SPIDER_DURATION "${ZAP_AJAX_SPIDER_DURATION:-10}"
set_env ZAP_PASSIVE_SCAN_ENABLED "${ZAP_PASSIVE_SCAN_ENABLED:-true}"
set_env ZAP_ACTIVE_SCAN_ENABLED "${ZAP_ACTIVE_SCAN_ENABLED:-true}"
set_env ZAP_REPORT_FORMATS "${ZAP_REPORT_FORMATS:-html,xml,json}"
set_env ZAP_REPORT_INCLUDE_DETAILS "${ZAP_REPORT_INCLUDE_DETAILS:-true}"
set_env ZAP_REPORT_TITLE "${ZAP_REPORT_TITLE:-ZAP Security Scan Report}"
set_env ZAP_EVIDENCE_TYPE "${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"
set_env ZAP_MAX_ALERTS_PER_RULE "${ZAP_MAX_ALERTS_PER_RULE:-10}"
set_env ZAP_MAX_SCAN_DURATION_PER_HOST "${ZAP_MAX_SCAN_DURATION_PER_HOST:-30}"
set_env ZAP_REQUEST_DELAY "${ZAP_REQUEST_DELAY:-0}"
set_env ZAP_LOG_LEVEL "${ZAP_LOG_LEVEL:-INFO}"
set_env ZAP_VERBOSE "${ZAP_VERBOSE:-false}"

if [[ -n "${API_DATA_FILE:-}" && -f "${API_DATA_FILE}" ]] && command -v jq >/dev/null 2>&1; then
  tmp=$(mktemp)
  jq '.apisToScan += []' "${API_DATA_FILE}" > "$tmp" && mv "$tmp" "${API_DATA_FILE}"
fi

validate_zap_config() {
  local miss=0
  for v in ICA_APP_URL IBM_SSO_USERNAME IBM_SSO_PASSWORD; do
    if [[ -z "${!v:-}" ]]; then
      echo "Missing required variable: $v" >&2
      miss=1
    fi
  done
  return $miss
}

print_zap_config() {
cat <<EOF
Target URL: ${ICA_APP_URL:-}
Context: ${ZAP_CONTEXT_NAME}
Timeout: ${ZAP_SCAN_TIMEOUT}
Depth: ${ZAP_MAX_DEPTH}
Threads: ${ZAP_THREAD_COUNT}
Threshold: ${ZAP_ALERT_THRESHOLD}
Report Dir: ${ZAP_REPORT_DIR}
EOF
}

if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
  validate_zap_config || true
fi
