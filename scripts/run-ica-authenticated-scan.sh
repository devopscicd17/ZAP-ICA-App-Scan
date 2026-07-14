#!/usr/bin/env bash
#
# IBM Toolchain Pipeline Integration for ZAP Authenticated Scan
# This script integrates ZAP authenticated scanning into IBM Cloud Toolchain pipelines
# for ICA applications using IBM SSO authentication
#
# Usage in .pipeline-config.yaml:
#   dynamic-scan:
#     script: |
#       source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE:-$(pwd)}"

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# =============================================================================
# Logging Functions
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# =============================================================================
# Environment Setup
# =============================================================================

setup_environment() {
    log_info "Setting up environment for ZAP authenticated scan..."
    
    # Source the ICA-specific environment configuration
    if [[ -f "${SCRIPT_DIR}/zap-custom-scripts/.env.ica-authenticated-scan.sh" ]]; then
        log_info "Loading ICA authentication configuration..."
        # shellcheck disable=SC1091
        source "${SCRIPT_DIR}/zap-custom-scripts/.env.ica-authenticated-scan.sh"
    else
        log_error "ICA authentication configuration not found"
        exit 1
    fi
    
    # Get app URL from pipeline environment
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        # Try to get from app-url pipeline variable
        ICA_APP_URL="${ICA_APP_URL:-${APP_URL:-}}"
        if [[ -z "$ICA_APP_URL" ]] && command -v get_env >/dev/null 2>&1; then
            ICA_APP_URL="$(get_env app-url "")"
        fi
        
        if [[ -z "${ICA_APP_URL}" ]]; then
            log_error "ICA_APP_URL not set. Please provide the application URL."
            log_error "Set it via: export ICA_APP_URL='https://your-ica-app.ibm.com'"
            log_error "Or set 'app-url' in pipeline configuration"
            exit 1
        fi
        
        export ICA_APP_URL
    fi
    
    # Get credentials from pipeline secrets
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        IBM_SSO_USERNAME="$(get_env ibm-sso-username "")"
        if [[ -z "${IBM_SSO_USERNAME}" ]]; then
            log_error "IBM_SSO_USERNAME not set. Please configure IBM SSO credentials."
            exit 1
        fi
        export IBM_SSO_USERNAME
    fi
    
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        IBM_SSO_PASSWORD="$(get_env ibm-sso-password "")"
        if [[ -z "${IBM_SSO_PASSWORD}" ]]; then
            log_error "IBM_SSO_PASSWORD not set. Please configure IBM SSO credentials."
            exit 1
        fi
        export IBM_SSO_PASSWORD
    fi
    
    # Set report directory to pipeline workspace
    export ZAP_REPORT_DIR="${WORKSPACE_DIR}/zap-reports"
    mkdir -p "${ZAP_REPORT_DIR}"
    
    log_success "Environment setup completed"
    
    # Print configuration summary
    if command -v print_zap_config &> /dev/null; then
        print_zap_config
    fi
}

# =============================================================================
# Docker Setup for ZAP
# =============================================================================

setup_zap_docker() {
    log_info "Setting up ZAP Docker container..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not available. ZAP requires Docker to run."
        exit 1
    fi
    
    # Pull ZAP Docker image
    log_info "Pulling OWASP ZAP Docker image..."
    docker pull ghcr.io/zaproxy/zaproxy:stable || {
        log_error "Failed to pull ZAP Docker image"
        exit 1
    }
    
    log_success "ZAP Docker setup completed"
}

# =============================================================================
# Run ZAP Scan
# =============================================================================

run_zap_scan() {
    log_info "Starting ZAP authenticated full scan..."
    
    local scan_script="${SCRIPT_DIR}/zap-full-scan-authenticated.sh"
    
    if [[ ! -f "${scan_script}" ]]; then
        log_error "ZAP scan script not found: ${scan_script}"
        exit 1
    fi
    
    # Make script executable
    chmod +x "${scan_script}"
    
    # Run the scan
    log_info "Executing ZAP full scan with IBM SSO authentication..."
    
    if bash "${scan_script}"; then
        log_success "ZAP scan completed successfully"
        return 0
    else
        log_error "ZAP scan failed or found security issues"
        return 1
    fi
}

# =============================================================================
# Alternative: Run ZAP in Docker
# =============================================================================

run_zap_scan_docker() {
    log_info "Starting ZAP authenticated scan in Docker..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local container_name="zap-scan-${timestamp}"
    
    # Prepare ZAP configuration
    local zap_config_dir="${WORKSPACE_DIR}/.zap"
    mkdir -p "${zap_config_dir}"
    
    # Copy authentication script to ZAP config directory
    cp "${SCRIPT_DIR}/zap-custom-scripts/ibm-sso-auth.js" "${zap_config_dir}/"
    
    # Create ZAP automation framework configuration
    cat > "${zap_config_dir}/automation.yaml" <<EOF
---
env:
  contexts:
    - name: ${ZAP_CONTEXT_NAME}
      urls:
        - ${ICA_APP_URL}
      includePaths:
        - "${ICA_APP_URL}.*"
      excludePaths:
        - ".*logout.*"
        - ".*signout.*"
      authentication:
        method: "script"
        parameters:
          script: "IBM-SSO-Auth"
          scriptEngine: "Oracle Nashorn"
        verification:
          method: "response"
          loggedInRegex: "\\\\QLogout\\\\E|\\\\Qlogout\\\\E"
          loggedOutRegex: "\\\\QLogin\\\\E|\\\\Qlogin\\\\E|\\\\Qw3id.sso.ibm.com\\\\E"
      users:
        - name: "IBMSSOUser"
          credentials:
            username: "${IBM_SSO_USERNAME}"
            password: "${IBM_SSO_PASSWORD}"

jobs:
  - type: spider
    parameters:
      context: ${ZAP_CONTEXT_NAME}
      user: IBMSSOUser
      maxDuration: 10
      maxDepth: ${ZAP_MAX_DEPTH}
      
  - type: passiveScan-wait
    parameters:
      maxDuration: 5
      
  - type: activeScan
    parameters:
      context: ${ZAP_CONTEXT_NAME}
      user: IBMSSOUser
      maxDuration: ${ZAP_SCAN_TIMEOUT}
      
  - type: report
    parameters:
      template: traditional-html
      reportDir: /zap/wrk/reports
      reportFile: zap-report-${timestamp}.html
      
  - type: report
    parameters:
      template: traditional-xml
      reportDir: /zap/wrk/reports
      reportFile: zap-report-${timestamp}.xml
      
  - type: report
    parameters:
      template: traditional-json
      reportDir: /zap/wrk/reports
      reportFile: zap-report-${timestamp}.json
EOF
    
    log_info "Running ZAP Docker container..."
    
    # Run ZAP in Docker with automation framework
    docker run --rm \
        --name "${container_name}" \
        -v "${zap_config_dir}:/zap/wrk/config:ro" \
        -v "${ZAP_REPORT_DIR}:/zap/wrk/reports:rw" \
        -e "ZAP_AUTH_HEADER_VALUE=${IBM_SSO_USERNAME}:${IBM_SSO_PASSWORD}" \
        owasp/zap2docker-stable:latest \
        zap.sh -cmd \
        -autorun /zap/wrk/config/automation.yaml \
        -config api.disablekey=true \
        || {
            log_error "ZAP Docker scan failed"
            return 1
        }
    
    log_success "ZAP Docker scan completed"
    return 0
}

# =============================================================================
# Collect Evidence for IBM Toolchain
# =============================================================================

collect_evidence() {
    log_info "Collecting scan evidence for IBM Toolchain..."
    
    local evidence_type="${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # Find the latest reports
    local html_report=$(find "${ZAP_REPORT_DIR}" -name "zap-report-*.html" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    local xml_report=$(find "${ZAP_REPORT_DIR}" -name "zap-report-*.xml" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    local json_report=$(find "${ZAP_REPORT_DIR}" -name "zap-report-*.json" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    
    if [[ -z "${html_report}" ]] || [[ ! -f "${html_report}" ]]; then
        log_warning "No HTML report found to collect as evidence"
        return 1
    fi
    
    # Create evidence summary
    local evidence_summary="${ZAP_REPORT_DIR}/evidence-summary-${timestamp}.json"
    
    cat > "${evidence_summary}" <<EOF
{
  "evidence_type": "${evidence_type}",
  "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target_url": "${ICA_APP_URL}",
  "scan_type": "ZAP Full Scan - Authenticated",
  "authentication_method": "IBM SSO (Script-based)",
  "reports": {
    "html": "$(basename "${html_report}")",
    "xml": "$(basename "${xml_report}")",
    "json": "$(basename "${json_report}")"
  },
  "configuration": {
    "context": "${ZAP_CONTEXT_NAME}",
    "max_depth": ${ZAP_MAX_DEPTH},
    "thread_count": ${ZAP_THREAD_COUNT},
    "scan_timeout": ${ZAP_SCAN_TIMEOUT},
    "alert_threshold": "${ZAP_ALERT_THRESHOLD}"
  }
}
EOF
    
    log_success "Evidence collected: ${evidence_summary}"
    
    # If running in IBM Toolchain, save evidence
    if command -v save_artifact &> /dev/null; then
        log_info "Saving evidence to IBM Toolchain..."
        save_artifact "zap-scan-evidence" \
            "type=${evidence_type}" \
            "path=${html_report}" \
            "summary=${evidence_summary}"
    fi
    
    return 0
}

# =============================================================================
# Analyze Results
# =============================================================================

analyze_results() {
    log_info "Analyzing scan results..."
    
    local json_report=$(find "${ZAP_REPORT_DIR}" -name "zap-report-*.json" -type f -printf '%T@ %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
    
    if [[ -z "${json_report}" ]] || [[ ! -f "${json_report}" ]]; then
        log_error "No JSON report found for analysis"
        return 1
    fi
    
    # Count alerts by risk level
    local high_alerts=$(jq '[.alerts[] | select(.risk == "High")] | length' "${json_report}" 2>/dev/null || echo "0")
    local medium_alerts=$(jq '[.alerts[] | select(.risk == "Medium")] | length' "${json_report}" 2>/dev/null || echo "0")
    local low_alerts=$(jq '[.alerts[] | select(.risk == "Low")] | length' "${json_report}" 2>/dev/null || echo "0")
    local info_alerts=$(jq '[.alerts[] | select(.risk == "Informational")] | length' "${json_report}" 2>/dev/null || echo "0")
    
    log_info "Scan Results Summary:"
    log_info "  High Risk Alerts: ${high_alerts}"
    log_info "  Medium Risk Alerts: ${medium_alerts}"
    log_info "  Low Risk Alerts: ${low_alerts}"
    log_info "  Informational Alerts: ${info_alerts}"
    
    # Check against threshold
    local fail_scan=false
    case "${ZAP_ALERT_THRESHOLD}" in
        HIGH)
            if [[ ${high_alerts} -gt 0 ]]; then
                log_error "Scan failed: Found ${high_alerts} HIGH risk alerts"
                fail_scan=true
            fi
            ;;
        MEDIUM)
            if [[ ${high_alerts} -gt 0 ]] || [[ ${medium_alerts} -gt 0 ]]; then
                log_error "Scan failed: Found ${high_alerts} HIGH and ${medium_alerts} MEDIUM risk alerts"
                fail_scan=true
            fi
            ;;
        LOW)
            if [[ ${high_alerts} -gt 0 ]] || [[ ${medium_alerts} -gt 0 ]] || [[ ${low_alerts} -gt 0 ]]; then
                log_error "Scan failed: Found vulnerabilities above LOW threshold"
                fail_scan=true
            fi
            ;;
    esac
    
    if [[ "${fail_scan}" == "true" ]]; then
        return 1
    else
        log_success "Scan passed: No alerts above ${ZAP_ALERT_THRESHOLD} threshold"
        return 0
    fi
}

# =============================================================================
# Main Execution
# =============================================================================

main() {
    log_info "=========================================="
    log_info "ZAP Authenticated Scan for ICA Applications"
    log_info "IBM Toolchain Pipeline Integration"
    log_info "=========================================="
    
    local exit_code=0
    
    # Setup environment
    setup_environment || exit_code=$?
    
    if [[ ${exit_code} -ne 0 ]]; then
        log_error "Environment setup failed"
        return ${exit_code}
    fi
    
    # Determine scan method (native or Docker)
    local use_docker="${ZAP_USE_DOCKER:-true}"
    
    if [[ "${use_docker}" == "true" ]]; then
        setup_zap_docker || exit_code=$?
        if [[ ${exit_code} -eq 0 ]]; then
            run_zap_scan_docker || exit_code=$?
        fi
    else
        run_zap_scan || exit_code=$?
    fi
    
    # Collect evidence regardless of scan result
    collect_evidence || log_warning "Failed to collect evidence"
    
    # Analyze results
    if [[ ${exit_code} -eq 0 ]]; then
        analyze_results || exit_code=$?
    fi
    
    # Final status
    if [[ ${exit_code} -eq 0 ]]; then
        log_success "=========================================="
        log_success "ZAP Authenticated Scan Completed Successfully"
        log_success "=========================================="
    else
        log_error "=========================================="
        log_error "ZAP Authenticated Scan Failed"
        log_error "=========================================="
    fi
    
    return ${exit_code}
}

# Run main function if script is executed directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit $?
fi


