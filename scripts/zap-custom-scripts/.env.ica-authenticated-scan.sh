#!/bin/false
# shellcheck shell=bash
# shebang to indicate it can only be invoked using source . command

#
# Environment Configuration for ZAP Authenticated Scan of ICA Applications
# This file configures ZAP for authenticated scanning of IBM Consulting Advantage apps
#
#!/usr/bin/env bash

# Compatibility for IBM Continuous Delivery

if ! command -v set_env >/dev/null 2>&1; then
    set_env() {
        export "$1=$2"
    }
fi

if ! command -v get_env >/dev/null 2>&1; then
    get_env() {
        local var="$1"
        local default="${2:-}"
        printenv "$var" || echo "$default"
    }
fi
# =============================================================================
# IBM SSO Authentication Configuration
# =============================================================================

# IBM SSO Login URL (default for IBM w3id SSO)
set_env IBM_SSO_LOGIN_URL "${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"

# IBM SSO Username (should be set in pipeline secrets)
# set_env IBM_SSO_USERNAME "your-email@ibm.com"

# IBM SSO Password (should be set in pipeline secrets)
# set_env IBM_SSO_PASSWORD "your-password"

# ICA Application URL (should be set in pipeline or environment)
# set_env ICA_APP_URL "https://your-ica-app.ibm.com"

# =============================================================================
# ZAP Scan Configuration
# =============================================================================

# ZAP Context Name
set_env ZAP_CONTEXT_NAME "${ZAP_CONTEXT_NAME:-ICA-App-Context}"

# Maximum crawl depth for spider
set_env ZAP_MAX_DEPTH "${ZAP_MAX_DEPTH:-5}"

# Number of threads for scanning
set_env ZAP_THREAD_COUNT "${ZAP_THREAD_COUNT:-5}"

# Scan timeout in minutes
set_env ZAP_SCAN_TIMEOUT "${ZAP_SCAN_TIMEOUT:-60}"

# Alert threshold (HIGH, MEDIUM, LOW, or INFORMATIONAL)
# Scan will fail if alerts above this threshold are found
set_env ZAP_ALERT_THRESHOLD "${ZAP_ALERT_THRESHOLD:-MEDIUM}"

# Report directory
set_env ZAP_REPORT_DIR "${ZAP_REPORT_DIR:-./zap-reports}"

# =============================================================================
# ZAP Filter Options
# =============================================================================

# Set filter options to prevent false positives
# Options: High, Medium, Low, Informational
set_env filter-options "Low,Informational"

# =============================================================================
# URL Exclusions
# =============================================================================

# Exclude logout URLs to prevent session termination during scan
set_env ZAP_EXCLUDE_URLS "${ZAP_EXCLUDE_URLS:-.*logout.*,.*signout.*,.*sign-out.*}"

# Additional exclusions for common non-scannable endpoints
# Uncomment and modify as needed for your application
# set_env ZAP_EXCLUDE_URLS "${ZAP_EXCLUDE_URLS},.*\/download\/.*,.*\/export\/.*"

# =============================================================================
# Authentication Indicators
# =============================================================================

# Logged in indicator regex (adjust based on your application)
# This regex should match content that appears only when user is logged in
set_env ZAP_LOGGED_IN_INDICATOR "${ZAP_LOGGED_IN_INDICATOR:-\\QLogout\\E|\\Qlogout\\E|\\QSign Out\\E|\\Qsign-out\\E}"

# Logged out indicator regex (adjust based on your application)
# This regex should match content that appears only when user is logged out
set_env ZAP_LOGGED_OUT_INDICATOR "${ZAP_LOGGED_OUT_INDICATOR:-\\QLogin\\E|\\Qlogin\\E|\\QSign In\\E|\\Qsign-in\\E|\\Qw3id.sso.ibm.com\\E}"

# =============================================================================
# Scan Policy Configuration
# =============================================================================

# Enable/disable specific scan rules
# Uncomment to customize scan policy

# Disable time-consuming or noisy rules
# set_env ZAP_DISABLE_RULES "10202,10201,10096"

# Enable only specific rules (comma-separated rule IDs)
# set_env ZAP_ENABLE_RULES "40012,40014,40016,40017,40018"

# =============================================================================
# API Scan Configuration
# =============================================================================

# Configure API data file if API scanning is needed
if [ -f "${API_DATA_FILE}" ]; then
    TMP_API_DATA_FILE=$(mktemp)
    
    # Add specific API endpoints to scan
    # Modify this section based on your ICA application's API structure
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

# Session timeout in seconds (default: 1800 = 30 minutes)
set_env ZAP_SESSION_TIMEOUT "${ZAP_SESSION_TIMEOUT:-1800}"

# Re-authentication on session timeout
set_env ZAP_REAUTHENTICATE_ON_TIMEOUT "${ZAP_REAUTHENTICATE_ON_TIMEOUT:-true}"

# =============================================================================
# Advanced Configuration
# =============================================================================

# Enable AJAX spider for single-page applications
set_env ZAP_AJAX_SPIDER_ENABLED "${ZAP_AJAX_SPIDER_ENABLED:-false}"

# AJAX spider browser (firefox, chrome, htmlunit)
set_env ZAP_AJAX_SPIDER_BROWSER "${ZAP_AJAX_SPIDER_BROWSER:-firefox}"

# Maximum duration for AJAX spider in minutes
set_env ZAP_AJAX_SPIDER_DURATION "${ZAP_AJAX_SPIDER_DURATION:-10}"

# Enable passive scanning
set_env ZAP_PASSIVE_SCAN_ENABLED "${ZAP_PASSIVE_SCAN_ENABLED:-true}"

# Enable active scanning
set_env ZAP_ACTIVE_SCAN_ENABLED "${ZAP_ACTIVE_SCAN_ENABLED:-true}"

# =============================================================================
# Reporting Configuration
# =============================================================================

# Report formats to generate (comma-separated: html,xml,json,md)
set_env ZAP_REPORT_FORMATS "${ZAP_REPORT_FORMATS:-html,xml,json,md}"

# Include request/response details in reports
set_env ZAP_REPORT_INCLUDE_DETAILS "${ZAP_REPORT_INCLUDE_DETAILS:-true}"

# Report title
set_env ZAP_REPORT_TITLE "${ZAP_REPORT_TITLE:-ZAP Security Scan Report - ICA Application}"

# =============================================================================
# IBM Cloud Toolchain Integration
# =============================================================================

# Evidence collection for compliance
set_env ZAP_EVIDENCE_TYPE "${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"

# Evidence locker integration
set_env ZAP_EVIDENCE_LOCKER_ENABLED "${ZAP_EVIDENCE_LOCKER_ENABLED:-true}"

# =============================================================================
# Proxy Configuration (if needed)
# =============================================================================

# HTTP Proxy settings (uncomment if corporate proxy is required)
# set_env HTTP_PROXY "${HTTP_PROXY:-http://proxy.example.com:8080}"
# set_env HTTPS_PROXY "${HTTPS_PROXY:-http://proxy.example.com:8080}"
# set_env NO_PROXY "${NO_PROXY:-localhost,127.0.0.1,.ibm.com}"

# =============================================================================
# Custom Headers
# =============================================================================

# Add custom headers for all requests (if required by ICA app)
# Format: "Header-Name: Header-Value"
# set_env ZAP_CUSTOM_HEADERS "X-Custom-Header: value,X-Another-Header: value2"

# =============================================================================
# Performance Tuning
# =============================================================================

# Maximum number of alerts per rule
set_env ZAP_MAX_ALERTS_PER_RULE "${ZAP_MAX_ALERTS_PER_RULE:-10}"

# Maximum scan duration per host in minutes
set_env ZAP_MAX_SCAN_DURATION_PER_HOST "${ZAP_MAX_SCAN_DURATION_PER_HOST:-30}"

# Delay between requests in milliseconds (to avoid overwhelming the server)
set_env ZAP_REQUEST_DELAY "${ZAP_REQUEST_DELAY:-0}"

# =============================================================================
# Logging Configuration
# =============================================================================

# ZAP log level (DEBUG, INFO, WARN, ERROR)
set_env ZAP_LOG_LEVEL "${ZAP_LOG_LEVEL:-INFO}"

# Enable verbose logging
set_env ZAP_VERBOSE "${ZAP_VERBOSE:-false}"

# =============================================================================
# Validation
# =============================================================================

# Validate required environment variables
validate_zap_config() {
    local missing_vars=()
    
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        missing_vars+=("ICA_APP_URL")
    fi
    
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        missing_vars+=("IBM_SSO_USERNAME")
    fi
    
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        missing_vars+=("IBM_SSO_PASSWORD")
    fi
    
    if [[ ${#missing_vars[@]} -gt 0 ]]; then
        echo "ERROR: Missing required environment variables for ZAP authenticated scan:" >&2
        printf '  - %s\n' "${missing_vars[@]}" >&2
        echo "" >&2
        echo "Please set these variables in your pipeline configuration or environment." >&2
        return 1
    fi
    
    return 0
}

# Run validation if not in sourcing mode
if [[ "${BASH_SOURCE[0]}" != "${0}" ]]; then
    # File is being sourced
    validate_zap_config || echo "WARNING: ZAP configuration validation failed" >&2
fi

# =============================================================================
# Helper Functions
# =============================================================================

# Function to print ZAP configuration summary
print_zap_config() {
    echo "ZAP Authenticated Scan Configuration:"
    echo "======================================"
    echo "Target URL: ${ICA_APP_URL:-<not set>}"
    echo "SSO Login URL: ${IBM_SSO_LOGIN_URL}"
    echo "Context Name: ${ZAP_CONTEXT_NAME}"
    echo "Max Depth: ${ZAP_MAX_DEPTH}"
    echo "Thread Count: ${ZAP_THREAD_COUNT}"
    echo "Scan Timeout: ${ZAP_SCAN_TIMEOUT} minutes"
    echo "Alert Threshold: ${ZAP_ALERT_THRESHOLD}"
    echo "Report Directory: ${ZAP_REPORT_DIR}"
    echo "AJAX Spider: ${ZAP_AJAX_SPIDER_ENABLED}"
    echo "Passive Scan: ${ZAP_PASSIVE_SCAN_ENABLED}"
    echo "Active Scan: ${ZAP_ACTIVE_SCAN_ENABLED}"
    echo "======================================"
}

# Export function for use in other scripts
export -f print_zap_config 2>/dev/null || true
