#!/usr/bin/env bash
#
# ZAP Full Scan with IBM SSO Authentication for ICA Applications
# Performs an authenticated OWASP ZAP full scan (spider + active) against ICA
# apps hosted in IBM Consulting Advantage using IBM w3id SAML SSO.
#
# Required environment variables:
#   ICA_APP_URL        — Target ICA application URL
#   IBM_SSO_USERNAME   — IBM w3id email address
#   IBM_SSO_PASSWORD   — IBM w3id password
#
# Optional environment variables (defaults shown):
#   IBM_SSO_LOGIN_URL  — https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20
#   ZAP_SCAN_TIMEOUT   — 60  (minutes)
#   ZAP_REPORT_DIR     — ./zap-reports
#   ZAP_CONTEXT_NAME   — ICA-App-Context
#   ZAP_MAX_DEPTH      — 5
#   ZAP_THREAD_COUNT   — 5
#   ZAP_ALERT_THRESHOLD — MEDIUM  (HIGH | MEDIUM | LOW | INFORMATIONAL)
#   ZAP_EXCLUDE_URLS   — .*logout.*,.*signout.*,.*sign-out.*
#   ZAP_DOCKER_IMAGE   — ghcr.io/zaproxy/zaproxy:stable
#   ZAP_CONTAINER_NAME — zap-scan-container
#   ZAP_API_KEY        — auto-generated UUID if not set
#   ZAP_LOG_LEVEL      — INFO
#
# Exit codes:
#   0 — scan completed, no alerts above threshold
#   1 — scan completed, alerts found above threshold OR scan error

set -euo pipefail

# =============================================================================
# Colour helpers (disabled automatically when not a TTY)
# =============================================================================
if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

log_info()    { echo -e "${BLUE}[INFO]${NC}    $*"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC}   $*" >&2; }

# =============================================================================
# Validate required environment variables
# =============================================================================
validate_environment() {
    log_info "Validating environment variables..."

    local missing=()
    [[ -z "${ICA_APP_URL:-}"      ]] && missing+=("ICA_APP_URL")
    [[ -z "${IBM_SSO_USERNAME:-}" ]] && missing+=("IBM_SSO_USERNAME")
    [[ -z "${IBM_SSO_PASSWORD:-}" ]] && missing+=("IBM_SSO_PASSWORD")

    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required environment variables:"
        printf '  %s\n' "${missing[@]}" >&2
        log_error "Example:"
        log_error "  export ICA_APP_URL='https://your-ica-app.ibm.com'"
        log_error "  export IBM_SSO_USERNAME='user@ibm.com'"
        log_error "  export IBM_SSO_PASSWORD='secret'"
        exit 1
    fi

    log_success "Environment validation passed"
}

# =============================================================================
# Set default values
# =============================================================================
set_defaults() {
    export IBM_SSO_LOGIN_URL="${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"
    export ZAP_SCAN_TIMEOUT="${ZAP_SCAN_TIMEOUT:-60}"
    export ZAP_REPORT_DIR="${ZAP_REPORT_DIR:-./zap-reports}"
    export ZAP_CONTEXT_NAME="${ZAP_CONTEXT_NAME:-ICA-App-Context}"
    export ZAP_MAX_DEPTH="${ZAP_MAX_DEPTH:-5}"
    export ZAP_THREAD_COUNT="${ZAP_THREAD_COUNT:-5}"
    export ZAP_ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
    export ZAP_EXCLUDE_URLS="${ZAP_EXCLUDE_URLS:-.*logout.*,.*signout.*,.*sign-out.*}"
    # Prefer the newer ghcr.io image; fall back to DockerHub for older pipelines
    export ZAP_DOCKER_IMAGE="${ZAP_DOCKER_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
    export ZAP_CONTAINER_NAME="${ZAP_CONTAINER_NAME:-zap-scan-container}"
    export ZAP_LOG_LEVEL="${ZAP_LOG_LEVEL:-INFO}"

    # Generate a stable API key for this run
    if [[ -z "${ZAP_API_KEY:-}" ]]; then
        ZAP_API_KEY="$(cat /proc/sys/kernel/random/uuid 2>/dev/null \
                       || uuidgen 2>/dev/null \
                       || echo "zap-key-$(date +%s)")"
        export ZAP_API_KEY
    fi

    # Resolve absolute path for the report directory now
    mkdir -p "${ZAP_REPORT_DIR}"
    ZAP_REPORT_DIR_ABS="$(cd "${ZAP_REPORT_DIR}" && pwd)"
    export ZAP_REPORT_DIR_ABS

    # Single timestamp shared across all generated report files in this run
    SCAN_TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
    export SCAN_TIMESTAMP

    log_info "Configuration:"
    log_info "  Target URL       : ${ICA_APP_URL}"
    log_info "  SSO Login URL    : ${IBM_SSO_LOGIN_URL}"
    log_info "  Context Name     : ${ZAP_CONTEXT_NAME}"
    log_info "  Max Depth        : ${ZAP_MAX_DEPTH}"
    log_info "  Thread Count     : ${ZAP_THREAD_COUNT}"
    log_info "  Alert Threshold  : ${ZAP_ALERT_THRESHOLD}"
    log_info "  Scan Timeout     : ${ZAP_SCAN_TIMEOUT} minutes"
    log_info "  ZAP Docker Image : ${ZAP_DOCKER_IMAGE}"
    log_info "  Report Directory : ${ZAP_REPORT_DIR_ABS}"
    log_info "  Run Timestamp    : ${SCAN_TIMESTAMP}"
}

# =============================================================================
# Start ZAP daemon in Docker
# =============================================================================
start_zap_daemon() {
    log_info "Starting ZAP daemon in Docker..."

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not in PATH. Ensure the pipeline stage has 'dind: true'."
        exit 1
    fi
    log_info "Docker: $(docker --version)"

    # Remove any stale container with the same name
    if docker ps -a --format '{{.Names}}' | grep -q "^${ZAP_CONTAINER_NAME}$"; then
        log_info "Removing stale ZAP container..."
        docker rm -f "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
    fi

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    log_info "Starting ZAP container (${ZAP_CONTAINER_NAME}) on port 8080..."
    docker run -d \
        --name "${ZAP_CONTAINER_NAME}" \
        -u zap \
        -p 8080:8080 \
        -v "${ZAP_REPORT_DIR_ABS}:/zap/wrk:rw" \
        -v "${script_dir}/zap-custom-scripts:/zap/scripts:ro" \
        "${ZAP_DOCKER_IMAGE}" \
        zap.sh -daemon \
            -host 0.0.0.0 -port 8080 \
            -config api.key="${ZAP_API_KEY}" \
            -config api.addrs.addr.name='.*' \
            -config api.addrs.addr.regex=true \
            -config connection.timeoutInSecs=60 \
        > "${ZAP_REPORT_DIR_ABS}/zap-daemon.log" 2>&1

    log_success "ZAP container started"
    _wait_for_zap
}

# Wait until ZAP API is responsive or timeout
_wait_for_zap() {
    local max_wait=120
    local elapsed=0
    local interval=5

    log_info "Waiting for ZAP to be ready (up to ${max_wait}s)..."

    while [[ ${elapsed} -lt ${max_wait} ]]; do
        # Abort early if the container has already exited
        if ! docker ps --format '{{.Names}}' | grep -q "^${ZAP_CONTAINER_NAME}$"; then
            log_error "ZAP container exited unexpectedly. Logs:"
            docker logs "${ZAP_CONTAINER_NAME}" 2>&1 || true
            exit 1
        fi

        if curl -sf --max-time 5 \
               "http://localhost:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}" \
               > /dev/null 2>&1; then
            local zap_ver
            zap_ver="$(curl -s "http://localhost:8080/JSON/core/view/version/?apikey=${ZAP_API_KEY}" \
                        | grep -o '"version":"[^"]*"' | cut -d'"' -f4 || echo 'unknown')"
            log_success "ZAP daemon ready — version ${zap_ver}"
            return 0
        fi

        sleep "${interval}"
        elapsed=$(( elapsed + interval ))
        [[ $(( elapsed % 30 )) -eq 0 ]] && \
            log_info "  Still waiting... (${elapsed}/${max_wait}s)"
    done

    log_error "ZAP did not become ready within ${max_wait}s. Final logs:"
    docker logs --tail 50 "${ZAP_CONTAINER_NAME}" 2>&1 || true
    exit 1
}

# =============================================================================
# Helper: call ZAP JSON API and return response
# =============================================================================
_zap_api() {
    local endpoint="$1"; shift
    # remaining "$@" are -d key=value pairs
    curl -sf --max-time 30 "http://localhost:8080${endpoint}" "$@" || true
}

# =============================================================================
# Load IBM SSO authentication script into ZAP
# =============================================================================
load_auth_script() {
    log_info "Loading IBM SSO authentication script..."

    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local auth_script="${script_dir}/zap-custom-scripts/ibm-sso-auth.js"

    if [[ ! -f "${auth_script}" ]]; then
        log_error "Authentication script not found: ${auth_script}"
        exit 1
    fi

    # The script is mounted into the container at /zap/scripts/ibm-sso-auth.js
    local container_script="/zap/scripts/ibm-sso-auth.js"

    _zap_api "/JSON/script/action/load/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "scriptName=IBM-SSO-Auth" \
        -d "scriptType=authentication" \
        -d "scriptEngine=Oracle Nashorn" \
        -d "fileName=${container_script}" \
        -d "scriptDescription=IBM SSO SAML Authentication for ICA Applications" \
        > /dev/null

    log_success "Authentication script loaded"
}

# =============================================================================
# Configure ZAP context (scope, authentication, indicators)
# =============================================================================
configure_zap_context() {
    log_info "Configuring ZAP context (${ZAP_CONTEXT_NAME})..."

    # Create context — ZAP auto-assigns contextId=1 for the first context
    _zap_api "/JSON/context/action/newContext/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextName=${ZAP_CONTEXT_NAME}" > /dev/null

    # Include the target URL in context scope
    _zap_api "/JSON/context/action/includeInContext/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextName=${ZAP_CONTEXT_NAME}" \
        -d "regex=${ICA_APP_URL}.*" > /dev/null

    # Exclude sensitive URL patterns
    IFS=',' read -ra _excludes <<< "${ZAP_EXCLUDE_URLS}"
    for pattern in "${_excludes[@]}"; do
        log_info "  Excluding: ${pattern}"
        _zap_api "/JSON/context/action/excludeFromContext/" \
            -d "apikey=${ZAP_API_KEY}" \
            -d "contextName=${ZAP_CONTEXT_NAME}" \
            -d "regex=${pattern}" > /dev/null
    done

    # Set script-based authentication; pass ICA_APP_URL as a script parameter
    local encoded_url
    encoded_url="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
                    "${ICA_APP_URL}" 2>/dev/null \
                  || python -c "import urllib,sys; print(urllib.quote(sys.argv[1]))" \
                    "${ICA_APP_URL}" 2>/dev/null \
                  || echo "${ICA_APP_URL}")"

    _zap_api "/JSON/authentication/action/setAuthenticationMethod/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "authMethodName=scriptBasedAuthentication" \
        -d "authMethodConfigParams=scriptName%3DIBM-SSO-Auth%26ICA_APP_URL%3D${encoded_url}" \
        > /dev/null

    # Logged-in indicator — text that appears only when authenticated
    _zap_api "/JSON/authentication/action/setLoggedInIndicator/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "loggedInIndicatorRegex=\\QLogout\\E|\\Qlogout\\E|\\QSign Out\\E|\\Qsign-out\\E" \
        > /dev/null

    # Logged-out indicator — text that appears on the login page
    _zap_api "/JSON/authentication/action/setLoggedOutIndicator/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "loggedOutIndicatorRegex=\\QLogin\\E|\\Qlogin\\E|\\QSign In\\E|\\Qw3id.sso.ibm.com\\E" \
        > /dev/null

    log_success "ZAP context configured"
}

# =============================================================================
# Create authenticated user in ZAP
# =============================================================================
create_authenticated_user() {
    log_info "Creating authenticated user (IBMSSOUser)..."

    _zap_api "/JSON/users/action/newUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "name=IBMSSOUser" > /dev/null

    # URL-encode credentials before embedding in the config-params string
    local enc_user enc_pass
    enc_user="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
                 "${IBM_SSO_USERNAME}" 2>/dev/null || echo "${IBM_SSO_USERNAME}")"
    enc_pass="$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" \
                 "${IBM_SSO_PASSWORD}" 2>/dev/null || echo "${IBM_SSO_PASSWORD}")"

    _zap_api "/JSON/users/action/setAuthenticationCredentials/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "authCredentialsConfigParams=username%3D${enc_user}%26password%3D${enc_pass}" \
        > /dev/null

    _zap_api "/JSON/users/action/setUserEnabled/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "enabled=true" > /dev/null

    _zap_api "/JSON/forcedUser/action/setForcedUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "contextId=1" \
        -d "userId=0" > /dev/null

    _zap_api "/JSON/forcedUser/action/setForcedUserModeEnabled/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "boolean=true" > /dev/null

    log_success "Authenticated user created and forced-user mode enabled"
}

# =============================================================================
# Spider scan (crawl application as authenticated user)
# =============================================================================
perform_spider_scan() {
    log_info "Starting spider scan (max depth: ${ZAP_MAX_DEPTH})..."

    local scan_id
    scan_id="$(_zap_api "/JSON/spider/action/scanAsUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "url=${ICA_APP_URL}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "maxChildren=${ZAP_MAX_DEPTH}" \
        -d "recurse=true" | grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*' || echo "0")"

    log_info "Spider scan ID: ${scan_id}"

    local progress=0
    local spider_timeout=$(( ZAP_SCAN_TIMEOUT * 30 ))  # half of total timeout for spider
    local elapsed=0

    while [[ "${progress}" != "100" ]]; do
        progress="$(_zap_api "/JSON/spider/view/status/" \
            -d "apikey=${ZAP_API_KEY}" \
            -d "scanId=${scan_id}" | grep -o '"status":"[0-9]*"' | grep -o '[0-9]*' || echo "0")"
        log_info "  Spider progress: ${progress}%"

        if [[ "${progress}" == "100" ]]; then break; fi

        sleep 5
        elapsed=$(( elapsed + 5 ))
        if [[ ${elapsed} -ge ${spider_timeout} ]]; then
            log_warning "Spider timeout reached — stopping spider"
            _zap_api "/JSON/spider/action/stop/" \
                -d "apikey=${ZAP_API_KEY}" \
                -d "scanId=${scan_id}" > /dev/null
            break
        fi
    done

    local urls_found
    urls_found="$(_zap_api "/JSON/spider/view/numberOfResultsForScan/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "scanId=${scan_id}" | grep -o '[0-9]*' | head -1 || echo 'unknown')"
    log_success "Spider scan completed — URLs found: ${urls_found}"
}

# =============================================================================
# Active scan (attack application as authenticated user)
# =============================================================================
perform_active_scan() {
    log_info "Starting active scan (timeout: ${ZAP_SCAN_TIMEOUT} minutes)..."

    local scan_id
    scan_id="$(_zap_api "/JSON/ascan/action/scanAsUser/" \
        -d "apikey=${ZAP_API_KEY}" \
        -d "url=${ICA_APP_URL}" \
        -d "contextId=1" \
        -d "userId=0" \
        -d "recurse=true" \
        -d "inScopeOnly=true" | grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*' || echo "0")"

    log_info "Active scan ID: ${scan_id}"

    local progress=0
    local start_ts
    start_ts="$(date +%s)"
    local timeout_s=$(( ZAP_SCAN_TIMEOUT * 60 ))

    while [[ "${progress}" != "100" ]]; do
        progress="$(_zap_api "/JSON/ascan/view/status/" \
            -d "apikey=${ZAP_API_KEY}" \
            -d "scanId=${scan_id}" | grep -o '"status":"[0-9]*"' | grep -o '[0-9]*' || echo "0")"
        log_info "  Active scan progress: ${progress}%"

        if [[ "${progress}" == "100" ]]; then break; fi

        local now elapsed
        now="$(date +%s)"
        elapsed=$(( now - start_ts ))
        if [[ ${elapsed} -ge ${timeout_s} ]]; then
            log_warning "Active scan timeout reached (${ZAP_SCAN_TIMEOUT} min) — stopping"
            _zap_api "/JSON/ascan/action/stop/" \
                -d "apikey=${ZAP_API_KEY}" \
                -d "scanId=${scan_id}" > /dev/null
            break
        fi

        sleep 10
    done

    log_success "Active scan completed"
}

# =============================================================================
# Generate all report formats
# =============================================================================
generate_reports() {
    log_info "Generating scan reports (timestamp: ${SCAN_TIMESTAMP})..."

    local base="${ZAP_REPORT_DIR_ABS}/zap-report-${SCAN_TIMESTAMP}"

    # HTML
    _zap_api "/OTHER/core/other/htmlreport/" \
        -d "apikey=${ZAP_API_KEY}" > "${base}.html"
    log_info "  HTML   : ${base}.html"

    # XML
    _zap_api "/OTHER/core/other/xmlreport/" \
        -d "apikey=${ZAP_API_KEY}" > "${base}.xml"
    log_info "  XML    : ${base}.xml"

    # JSON — ZAP /core/view/alerts returns {"alerts":[...]}
    _zap_api "/JSON/core/view/alerts/" \
        -d "apikey=${ZAP_API_KEY}" > "${base}.json"
    log_info "  JSON   : ${base}.json"

    # Markdown (available from ZAP 2.11+; gracefully skipped if absent)
    local md_response
    md_response="$(_zap_api "/OTHER/core/other/mdreport/" \
        -d "apikey=${ZAP_API_KEY}" 2>/dev/null || echo "")"
    if [[ -n "${md_response}" ]]; then
        echo "${md_response}" > "${base}.md"
        log_info "  Markdown: ${base}.md"
    fi

    log_success "Reports saved to: ${ZAP_REPORT_DIR_ABS}"
}

# =============================================================================
# Analyse results and compare against the configured threshold
# =============================================================================
analyze_results() {
    log_info "Analysing scan results against threshold: ${ZAP_ALERT_THRESHOLD}..."

    local json_report="${ZAP_REPORT_DIR_ABS}/zap-report-${SCAN_TIMESTAMP}.json"

    if [[ ! -f "${json_report}" ]]; then
        log_error "JSON report not found: ${json_report}"
        return 1
    fi

    # ZAP /core/view/alerts returns {"alerts":[...]} — use .alerts[] not .alerts[].risk
    local high med low info
    high="$(jq '[.alerts[] | select(.risk == "High")]   | length' "${json_report}" 2>/dev/null || echo 0)"
    med="$(jq  '[.alerts[] | select(.risk == "Medium")] | length' "${json_report}" 2>/dev/null || echo 0)"
    low="$(jq  '[.alerts[] | select(.risk == "Low")]    | length' "${json_report}" 2>/dev/null || echo 0)"
    info="$(jq '[.alerts[] | select(.risk == "Informational")] | length' "${json_report}" 2>/dev/null || echo 0)"

    log_info "Scan Results Summary:"
    log_info "  High Alerts          : ${high}"
    log_info "  Medium Alerts        : ${med}"
    log_info "  Low Alerts           : ${low}"
    log_info "  Informational Alerts : ${info}"

    # Write a machine-readable summary alongside the reports
    cat > "${ZAP_REPORT_DIR_ABS}/zap-results-${SCAN_TIMESTAMP}.json" <<EOF
{
  "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target_url": "${ICA_APP_URL}",
  "alert_threshold": "${ZAP_ALERT_THRESHOLD}",
  "alerts": {
    "high": ${high},
    "medium": ${med},
    "low": ${low},
    "informational": ${info}
  }
}
EOF

    local fail=false
    case "${ZAP_ALERT_THRESHOLD^^}" in
        HIGH)
            [[ ${high} -gt 0 ]] && { log_error "FAIL: ${high} HIGH alert(s) found"; fail=true; }
            ;;
        MEDIUM)
            { [[ ${high} -gt 0 ]] || [[ ${med} -gt 0 ]]; } && \
                { log_error "FAIL: ${high} HIGH and ${med} MEDIUM alert(s) found"; fail=true; }
            ;;
        LOW)
            { [[ ${high} -gt 0 ]] || [[ ${med} -gt 0 ]] || [[ ${low} -gt 0 ]]; } && \
                { log_error "FAIL: vulnerabilities found above LOW threshold"; fail=true; }
            ;;
        INFORMATIONAL)
            { [[ ${high} -gt 0 ]] || [[ ${med} -gt 0 ]] || [[ ${low} -gt 0 ]] || [[ ${info} -gt 0 ]]; } && \
                { log_error "FAIL: alerts found (threshold: INFORMATIONAL)"; fail=true; }
            ;;
    esac

    if [[ "${fail}" == "true" ]]; then
        return 1
    fi

    log_success "PASS: no alerts above ${ZAP_ALERT_THRESHOLD} threshold"
    return 0
}

# =============================================================================
# Cleanup Docker container
# =============================================================================
cleanup() {
    log_info "Cleaning up ZAP container..."
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${ZAP_CONTAINER_NAME}$"; then
        docker stop  "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
        docker rm -f "${ZAP_CONTAINER_NAME}" > /dev/null 2>&1 || true
        log_success "ZAP container removed"
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    log_info "=============================================="
    log_info " ZAP Full Scan with IBM SSO Authentication   "
    log_info "=============================================="

    trap cleanup EXIT

    validate_environment
    set_defaults
    start_zap_daemon
    load_auth_script
    configure_zap_context
    create_authenticated_user
    perform_spider_scan
    perform_active_scan
    generate_reports

    if analyze_results; then
        log_success "=============================================="
        log_success " ZAP Scan PASSED                              "
        log_success "=============================================="
        exit 0
    else
        log_error "=============================================="
        log_error " ZAP Scan FAILED — review reports             "
        log_error " Reports: ${ZAP_REPORT_DIR_ABS}               "
        log_error "=============================================="
        exit 1
    fi
}

main "$@"

# Made with Bob
