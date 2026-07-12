#!/usr/bin/env bash
#
# ZAP Full Scan with IBM SSO Authentication for ICA Applications
# This script performs an authenticated OWASP ZAP full scan against ICA apps
# hosted in IBM Consulting Advantage using IBM SSO authentication
#
# Required Environment Variables:
# - ICA_APP_URL: Target ICA application URL
# - IBM_SSO_USERNAME: IBM SSO username/email
# - IBM_SSO_PASSWORD: IBM SSO password
# - ZAP_API_KEY: ZAP API key (optional, generated if not provided)
#
# Optional Environment Variables:
# - IBM_SSO_LOGIN_URL: IBM SSO login endpoint (default: https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20)
# - ZAP_SCAN_TIMEOUT: Scan timeout in minutes (default: 60)
# - ZAP_REPORT_DIR: Directory for scan reports (default: ./zap-reports)
# - ZAP_CONTEXT_NAME: ZAP context name (default: ICA-App-Context)
# - ZAP_MAX_DEPTH: Maximum crawl depth (default: 5)
# - ZAP_THREAD_COUNT: Number of threads for scanning (default: 5)
# - ZAP_ALERT_THRESHOLD: Alert threshold (default: MEDIUM)
# - ZAP_EXCLUDE_URLS: Comma-separated list of URLs to exclude from scan

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
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

# Validate required environment variables
validate_environment() {
    log_info "Validating environment variables..."
    
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
        log_error "Missing required environment variables: ${missing_vars[*]}"
        log_error "Please set the following variables:"
        log_error "  export ICA_APP_URL='https://your-ica-app.ibm.com'"
        log_error "  export IBM_SSO_USERNAME='your-email@ibm.com'"
        log_error "  export IBM_SSO_PASSWORD='your-password'"
        exit 1
    fi
    
    log_success "Environment validation passed"
}

# Set default values
set_defaults() {
    export IBM_SSO_LOGIN_URL="${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"
    export ZAP_SCAN_TIMEOUT="${ZAP_SCAN_TIMEOUT:-60}"
    export ZAP_REPORT_DIR="${ZAP_REPORT_DIR:-./zap-reports}"
    export ZAP_CONTEXT_NAME="${ZAP_CONTEXT_NAME:-ICA-App-Context}"
    export ZAP_MAX_DEPTH="${ZAP_MAX_DEPTH:-5}"
    export ZAP_THREAD_COUNT="${ZAP_THREAD_COUNT:-5}"
    export ZAP_ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
    export ZAP_API_KEY="${ZAP_API_KEY:-$(uuidgen 2>/dev/null || cat /proc/sys/kernel/random/uuid 2>/dev/null || echo "zap-api-key-$(date +%s)")}"
    export ZAP_DOCKER_IMAGE="${ZAP_DOCKER_IMAGE:-owasp/zap2docker-stable}"
    export ZAP_CONTAINER_NAME="${ZAP_CONTAINER_NAME:-zap-scan-container}"
    
    # Create report directory with absolute path
    mkdir -p "${ZAP_REPORT_DIR}"
    export ZAP_REPORT_DIR_ABS="$(cd "${ZAP_REPORT_DIR}" && pwd)"
    
    log_info "Configuration:"
    log_info "  Target URL: ${ICA_APP_URL}"
    log_info "  SSO Login URL: ${IBM_SSO_LOGIN_URL}"
    log_info "  Context Name: ${ZAP_CONTEXT_NAME}"
    log_info "  Max Depth: ${ZAP_MAX_DEPTH}"
    log_info "  Thread Count: ${ZAP_THREAD_COUNT}"
    log_info "  Alert Threshold: ${ZAP_ALERT_THRESHOLD}"
    log_info "  Report Directory: ${ZAP_REPORT_DIR_ABS}"
    log_info "  Scan Timeout: ${ZAP_SCAN_TIMEOUT} minutes"
    log_info "  ZAP Docker Image: ${ZAP_DOCKER_IMAGE}"
}

# Start ZAP daemon using Docker
start_zap_daemon() {
    log_info "Starting ZAP daemon using Docker..."
    
    # Check if Docker is available
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        log_error "Please ensure Docker is available in the IBM Cloud Toolchain environment"
        exit 1
    fi
    
    log_info "Docker found: $(docker --version)"
    
    # Stop and remove any existing ZAP container
    if docker ps -a --format '{{.Names}}' | grep -q "^${ZAP_CONTAINER_NAME}$"; then
        log_info "Removing existing ZAP container..."
        docker rm -f "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
    fi
    
    # Get the script directory for mounting
    local script_dir="$(cd "$(dirname "$0")" && pwd)"
    
    # Start ZAP container in daemon mode
    log_info "Starting ZAP Docker container..."
    log_info "  Image: ${ZAP_DOCKER_IMAGE}"
    log_info "  Container: ${ZAP_CONTAINER_NAME}"
    log_info "  Port: 8080"
    
    docker run -d \
        --name "${ZAP_CONTAINER_NAME}" \
        -u zap \
        -p 8080:8080 \
        -v "${ZAP_REPORT_DIR_ABS}:/zap/wrk:rw" \
        -v "${script_dir}/zap-custom-scripts:/zap/scripts:ro" \
        "${ZAP_DOCKER_IMAGE}" \
        zap.sh -daemon -host 0.0.0.0 -port 8080 \
        -config api.key="${ZAP_API_KEY}" \
        -config api.addrs.addr.name=.* \
        -config api.addrs.addr.regex=true \
        > "${ZAP_REPORT_DIR}/zap-container.log" 2>&1
    
    if [[ $? -ne 0 ]]; then
        log_error "Failed to start ZAP Docker container"
        docker logs "${ZAP_CONTAINER_NAME}" 2>&1 || true
        exit 1
    fi
    
    log_success "ZAP container started: ${ZAP_CONTAINER_NAME}"
    
    # Wait for ZAP to be ready using proper API endpoint
    log_info "Waiting for ZAP to be ready (this may take 1-2 minutes)..."
    local max_wait=120
    local wait_count=0
    local check_interval=5
    
    while [[ ${wait_count} -lt ${max_wait} ]]; do
        # Check if container is still running
        if ! docker ps --format '{{.Names}}' | grep -q "^${ZAP_CONTAINER_NAME}$"; then
            log_error "ZAP container stopped unexpectedly"
            log_error "Container logs:"
            docker logs "${ZAP_CONTAINER_NAME}" 2>&1 || true
            exit 1
        fi
        
        # Try to connect to ZAP API
        if curl -s --max-time 5 "http://localhost:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}" > /dev/null 2>&1; then
            log_success "ZAP daemon is ready and responding"
            
            # Get ZAP version for confirmation
            local zap_version=$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}" | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
            log_info "ZAP version: ${zap_version}"
            return 0
        fi
        
        sleep ${check_interval}
        wait_count=$((wait_count + check_interval))
        
        if [[ $((wait_count % 15)) -eq 0 ]]; then
            log_info "Still waiting... (${wait_count}/${max_wait} seconds)"
        fi
        
        # Show container logs every 30 seconds
        if [[ $((wait_count % 30)) -eq 0 ]]; then
            log_info "Recent ZAP container logs:"
            docker logs --tail 10 "${ZAP_CONTAINER_NAME}" 2>&1 | head -n 5 || echo "  (logs not available yet)"
        fi
    done
    
    # Timeout reached
    log_error "ZAP daemon failed to start within ${max_wait} seconds"
    log_error "Full container logs:"
    docker logs "${ZAP_CONTAINER_NAME}" 2>&1 || true
    log_error "Container status:"
    docker ps -a --filter "name=${ZAP_CONTAINER_NAME}" || true
    exit 1
}

# Load authentication script into ZAP
load_auth_script() {
    log_info "Loading IBM SSO authentication script into ZAP..."
    
    local script_path="$(dirname "$0")/zap-custom-scripts/ibm-sso-auth.js"
    
    if [[ ! -f "${script_path}" ]]; then
        log_error "Authentication script not found: ${script_path}"
        exit 1
    fi
    
    # Load the script via ZAP API
    curl -s "http://localhost:8080/JSON/script/action/load/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "scriptName=IBM-SSO-Auth" \
        -d "scriptType=authentication" \
        -d "scriptEngine=Oracle Nashorn" \
        -d "fileName=${script_path}" \
        -d "scriptDescription=IBM SSO Authentication for ICA Applications" \
        > /dev/null
    
    log_success "Authentication script loaded"
}

# Create and configure ZAP context
configure_zap_context() {
    log_info "Configuring ZAP context..."
    
    # Create new context
    curl -s "http://localhost:8080/JSON/context/action/newContext/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextName=${ZAP_CONTEXT_NAME}" \
        > /dev/null
    
    # Include target URL in context
    curl -s "http://localhost:8080/JSON/context/action/includeInContext/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextName=${ZAP_CONTEXT_NAME}" \
        -d "regex=${ICA_APP_URL}.*" \
        > /dev/null
    
    # Exclude URLs if specified
    if [[ -n "${ZAP_EXCLUDE_URLS:-}" ]]; then
        IFS=',' read -ra EXCLUDE_ARRAY <<< "${ZAP_EXCLUDE_URLS}"
        for exclude_url in "${EXCLUDE_ARRAY[@]}"; do
            log_info "Excluding URL pattern: ${exclude_url}"
            curl -s "http://localhost:8080/JSON/context/action/excludeFromContext/" \
                -d "apikey=${ZAP_API_KEY}" \
                -d "contextName=${ZAP_CONTEXT_NAME}" \
                -d "regex=${exclude_url}" \
                > /dev/null
        done
    fi
    
    # Set authentication method to script-based
    curl -s "http://localhost:8080/JSON/authentication/action/setAuthenticationMethod/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "authMethodName=scriptBasedAuthentication" \
        -d "authMethodConfigParams=scriptName=IBM-SSO-Auth" \
        > /dev/null
    
    # Set logged in indicator (adjust based on your app)
    curl -s "http://localhost:8080/JSON/authentication/action/setLoggedInIndicator/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "loggedInIndicatorRegex=\\QLogout\\E|\\Qlogout\\E|\\QSign Out\\E" \
        > /dev/null
    
    # Set logged out indicator
    curl -s "http://localhost:8080/JSON/authentication/action/setLoggedOutIndicator/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "loggedOutIndicatorRegex=\\QLogin\\E|\\Qlogin\\E|\\QSign In\\E|\\Qw3id.sso.ibm.com\\E" \
        > /dev/null
    
    log_success "ZAP context configured"
}

# Create authenticated user
create_authenticated_user() {
    log_info "Creating authenticated user in ZAP..."
    
    # Create user
    curl -s "http://localhost:8080/JSON/users/action/newUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "name=IBMSSOUser" \
        > /dev/null
    
    # Set user credentials
    curl -s "http://localhost:8080/JSON/users/action/setAuthenticationCredentials/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "authCredentialsConfigParams=username=${IBM_SSO_USERNAME}%26password=${IBM_SSO_PASSWORD}" \
        > /dev/null
    
    # Enable user
    curl -s "http://localhost:8080/JSON/users/action/setUserEnabled/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "enabled=true" \
        > /dev/null
    
    log_success "Authenticated user created"
}

# Perform spider scan
perform_spider_scan() {
    log_info "Starting spider scan..."
    
    # Start spider as user
    local scan_id
    scan_id=$(curl -s "http://localhost:8080/JSON/spider/action/scanAsUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "url=${ICA_APP_URL}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "maxChildren=${ZAP_MAX_DEPTH}" \
        -d "recurse=true" | jq -r '.scan')
    
    log_info "Spider scan started with ID: ${scan_id}"
    
    # Monitor spider progress
    local progress=0
    while [[ ${progress} -lt 100 ]]; do
        progress=$(curl -s "http://localhost:8080/JSON/spider/view/status/" \
            -d "scanId=${scan_id}" | jq -r '.status')
        log_info "Spider progress: ${progress}%"
        sleep 5
    done
    
    log_success "Spider scan completed"
}

# Perform active scan
perform_active_scan() {
    log_info "Starting active scan..."
    
    # Start active scan as user
    local scan_id
    scan_id=$(curl -s "http://localhost:8080/JSON/ascan/action/scanAsUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "url=${ICA_APP_URL}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "recurse=true" \
        -d "inScopeOnly=true" \
        -d "scanPolicyName=" \
        -d "method=" \
        -d "postData=" | jq -r '.scan')
    
    log_info "Active scan started with ID: ${scan_id}"
    
    # Monitor active scan progress
    local progress=0
    local start_time=$(date +%s)
    local timeout_seconds=$((ZAP_SCAN_TIMEOUT * 60))
    
    while [[ ${progress} -lt 100 ]]; do
        progress=$(curl -s "http://localhost:8080/JSON/ascan/view/status/" \
            -d "scanId=${scan_id}" | jq -r '.status')
        log_info "Active scan progress: ${progress}%"
        
        # Check timeout
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        if [[ ${elapsed} -ge ${timeout_seconds} ]]; then
            log_warning "Scan timeout reached (${ZAP_SCAN_TIMEOUT} minutes)"
            curl -s "http://localhost:8080/JSON/ascan/action/stop/" \
                -d "apikey=${ZAP_API_KEY}" \
                -d "scanId=${scan_id}" > /dev/null
            break
        fi
        
        sleep 10
    done
    
    log_success "Active scan completed"
}

# Generate reports
generate_reports() {
    log_info "Generating scan reports..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    
    # HTML Report
    log_info "Generating HTML report..."
    curl -s "http://localhost:8080/OTHER/core/other/htmlreport/" \
        -d "apikey=${ZAP_API_KEY}" \
        > "${ZAP_REPORT_DIR}/zap-report-${timestamp}.html"
    
    # XML Report
    log_info "Generating XML report..."
    curl -s "http://localhost:8080/OTHER/core/other/xmlreport/" \
        -d "apikey=${ZAP_API_KEY}" \
        > "${ZAP_REPORT_DIR}/zap-report-${timestamp}.xml"
    
    # JSON Report
    log_info "Generating JSON report..."
    curl -s "http://localhost:8080/JSON/core/view/alerts/" \
        -d "apikey=${ZAP_API_KEY}" \
        > "${ZAP_REPORT_DIR}/zap-report-${timestamp}.json"
    
    # Markdown Report
    log_info "Generating Markdown report..."
    curl -s "http://localhost:8080/OTHER/core/other/mdreport/" \
        -d "apikey=${ZAP_API_KEY}" \
        > "${ZAP_REPORT_DIR}/zap-report-${timestamp}.md"
    
    log_success "Reports generated in: ${ZAP_REPORT_DIR}"
    log_info "  - HTML: zap-report-${timestamp}.html"
    log_info "  - XML: zap-report-${timestamp}.xml"
    log_info "  - JSON: zap-report-${timestamp}.json"
    log_info "  - Markdown: zap-report-${timestamp}.md"
}

# Analyze results and check thresholds
analyze_results() {
    log_info "Analyzing scan results..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local json_report="${ZAP_REPORT_DIR}/zap-report-${timestamp}.json"
    
    if [[ ! -f "${json_report}" ]]; then
        log_error "JSON report not found: ${json_report}"
        return 1
    fi
    
    # Count alerts by risk level
    local high_alerts=$(jq '[.alerts[] | select(.risk == "High")] | length' "${json_report}")
    local medium_alerts=$(jq '[.alerts[] | select(.risk == "Medium")] | length' "${json_report}")
    local low_alerts=$(jq '[.alerts[] | select(.risk == "Low")] | length' "${json_report}")
    local info_alerts=$(jq '[.alerts[] | select(.risk == "Informational")] | length' "${json_report}")
    
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
                log_error "Scan failed: Found ${high_alerts} HIGH risk alerts (threshold: HIGH)"
                fail_scan=true
            fi
            ;;
        MEDIUM)
            if [[ ${high_alerts} -gt 0 ]] || [[ ${medium_alerts} -gt 0 ]]; then
                log_error "Scan failed: Found ${high_alerts} HIGH and ${medium_alerts} MEDIUM risk alerts (threshold: MEDIUM)"
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

# Cleanup
cleanup() {
    log_info "Cleaning up..."
    
    # Stop and remove ZAP container
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${ZAP_CONTAINER_NAME}$"; then
        log_info "Stopping ZAP container..."
        docker stop "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
        log_info "Removing ZAP container..."
        docker rm "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
    fi
    
    log_success "Cleanup completed"
}

# Main execution
main() {
    log_info "Starting ZAP Full Scan with IBM SSO Authentication"
    log_info "=================================================="
    
    # Set trap for cleanup
    trap cleanup EXIT
    
    # Execute scan steps
    validate_environment
    set_defaults
    start_zap_daemon
    load_auth_script
    configure_zap_context
    create_authenticated_user
    perform_spider_scan
    perform_active_scan
    generate_reports
    
    # Analyze results and exit with appropriate code
    if analyze_results; then
        log_success "ZAP Full Scan completed successfully"
        exit 0
    else
        log_error "ZAP Full Scan completed with failures"
        exit 1
    fi
}

# Run main function
main "$@"

# Made with Bob
