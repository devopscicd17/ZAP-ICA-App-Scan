#!/bin/false
# shellcheck shell=bash
# shebang to indicate it can only be invoked using source . command

#
# Environment Configuration for ZAP Authenticated Scan of ICA Applications
# This file configures ZAP for authenticated scanning of IBM Consulting Advantage apps
#
# NOTE: Uses plain bash export — set_env is an IBM Tekton built-in that is not
# available when this file is sourced from a pipeline script directly.
#

# =============================================================================
# IBM SSO Authentication Configuration
# =============================================================================

# IBM SSO Login URL (default for IBM w3id SSO)
export IBM_SSO_LOGIN_URL="${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"

# IBM SSO Username — must be exported by the calling pipeline script via get_env
# export IBM_SSO_USERNAME="your-email@ibm.com"

# IBM SSO Password — must be exported by the calling pipeline script via get_env
# export IBM_SSO_PASSWORD="your-password"

# ICA Application URL — must be exported by the calling pipeline script via get_env
# export ICA_APP_URL="https://your-ica-app.ibm.com"

# =============================================================================
# ZAP Scan Configuration
# =============================================================================

export ZAP_CONTEXT_NAME="${ZAP_CONTEXT_NAME:-ICA-App-Context}"
export ZAP_MAX_DEPTH="${ZAP_MAX_DEPTH:-5}"
export ZAP_THREAD_COUNT="${ZAP_THREAD_COUNT:-5}"
export ZAP_SCAN_TIMEOUT="${ZAP_SCAN_TIMEOUT:-60}"
export ZAP_ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
export ZAP_REPORT_DIR="${ZAP_REPORT_DIR:-/zap/wrk}"

# =============================================================================
# ZAP Filter Options
# =============================================================================

export filter_options="${filter_options:-Low,Informational}"

# =============================================================================
# URL Exclusions
# =============================================================================

export ZAP_EXCLUDE_URLS="${ZAP_EXCLUDE_URLS:-.*logout.*,.*signout.*,.*sign-out.*}"

# =============================================================================
# Authentication Indicators
# =============================================================================

export ZAP_LOGGED_IN_INDICATOR="${ZAP_LOGGED_IN_INDICATOR:-\\QLogout\\E|\\Qlogout\\E|\\QSign Out\\E|\\Qsign-out\\E}"
export ZAP_LOGGED_OUT_INDICATOR="${ZAP_LOGGED_OUT_INDICATOR:-\\QLogin\\E|\\Qlogin\\E|\\QSign In\\E|\\Qsign-in\\E|\\Qw3id.sso.ibm.com\\E}"

# =============================================================================
# API Scan Configuration
# =============================================================================

if [[ -n "${API_DATA_FILE:-}" ]] && [[ -f "${API_DATA_FILE}" ]]; then
    TMP_API_DATA_FILE=$(mktemp)
    jq '.apisToScan += [
        {"path":"/api/health", "method":"get"},
        {"path":"/api/status", "method":"get"},
        {"path":"/api/v1/*", "method":"get"}
    ]' "${API_DATA_FILE}" > "${TMP_API_DATA_FILE}"
    cp -f "${TMP_API_DATA_FILE}" "${API_DATA_FILE}"
    rm -f "${TMP_API_DATA_FILE}"
fi

# =============================================================================
# Session Management
# =============================================================================

export ZAP_SESSION_TIMEOUT="${ZAP_SESSION_TIMEOUT:-1800}"
export ZAP_REAUTHENTICATE_ON_TIMEOUT="${ZAP_REAUTHENTICATE_ON_TIMEOUT:-true}"

# =============================================================================
# Advanced Configuration
# =============================================================================

export ZAP_AJAX_SPIDER_ENABLED="${ZAP_AJAX_SPIDER_ENABLED:-false}"
export ZAP_AJAX_SPIDER_BROWSER="${ZAP_AJAX_SPIDER_BROWSER:-firefox}"
export ZAP_AJAX_SPIDER_DURATION="${ZAP_AJAX_SPIDER_DURATION:-10}"
export ZAP_PASSIVE_SCAN_ENABLED="${ZAP_PASSIVE_SCAN_ENABLED:-true}"
export ZAP_ACTIVE_SCAN_ENABLED="${ZAP_ACTIVE_SCAN_ENABLED:-true}"

# =============================================================================
# Reporting Configuration
# =============================================================================

export ZAP_REPORT_FORMATS="${ZAP_REPORT_FORMATS:-html,xml,json,md}"
export ZAP_REPORT_INCLUDE_DETAILS="${ZAP_REPORT_INCLUDE_DETAILS:-true}"
export ZAP_REPORT_TITLE="${ZAP_REPORT_TITLE:-ZAP Security Scan Report - ICA Application}"

# =============================================================================
# IBM Cloud Toolchain Integration
# =============================================================================

export ZAP_EVIDENCE_TYPE="${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"
export ZAP_EVIDENCE_LOCKER_ENABLED="${ZAP_EVIDENCE_LOCKER_ENABLED:-true}"

# =============================================================================
# Performance Tuning
# =============================================================================

export ZAP_MAX_ALERTS_PER_RULE="${ZAP_MAX_ALERTS_PER_RULE:-10}"
export ZAP_MAX_SCAN_DURATION_PER_HOST="${ZAP_MAX_SCAN_DURATION_PER_HOST:-30}"
export ZAP_REQUEST_DELAY="${ZAP_REQUEST_DELAY:-0}"

# =============================================================================
# Logging Configuration
# =============================================================================

export ZAP_LOG_LEVEL="${ZAP_LOG_LEVEL:-INFO}"
export ZAP_VERBOSE="${ZAP_VERBOSE:-false}"

# =============================================================================
# Validation — call explicitly after all required vars are exported
# =============================================================================

validate_zap_config() {
    local missing_vars=()
    [[ -z "${ICA_APP_URL:-}" ]]      && missing_vars+=("ICA_APP_URL")
    [[ -z "${IBM_SSO_USERNAME:-}" ]] && missing_vars+=("IBM_SSO_USERNAME")
    [[ -z "${IBM_SSO_PASSWORD:-}" ]] && missing_vars+=("IBM_SSO_PASSWORD")

    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo "ERROR: Missing required environment variables:" >&2
        printf '  - %s\n' "${missing_vars[@]}" >&2
        return 1
    fi
    return 0
}

# =============================================================================
# Helper Functions
# =============================================================================

print_zap_config() {
    echo "ZAP Authenticated Scan Configuration:"
    echo "======================================"
    echo "Target URL      : ${ICA_APP_URL:-<not set>}"
    echo "SSO Login URL   : ${IBM_SSO_LOGIN_URL}"
    echo "Context Name    : ${ZAP_CONTEXT_NAME}"
    echo "Max Depth       : ${ZAP_MAX_DEPTH}"
    echo "Thread Count    : ${ZAP_THREAD_COUNT}"
    echo "Scan Timeout    : ${ZAP_SCAN_TIMEOUT} minutes"
    echo "Alert Threshold : ${ZAP_ALERT_THRESHOLD}"
    echo "Report Dir      : ${ZAP_REPORT_DIR}"
    echo "AJAX Spider     : ${ZAP_AJAX_SPIDER_ENABLED}"
    echo "Passive Scan    : ${ZAP_PASSIVE_SCAN_ENABLED}"
    echo "Active Scan     : ${ZAP_ACTIVE_SCAN_ENABLED}"
    echo "======================================"
}

export -f print_zap_config 2>/dev/null || true
