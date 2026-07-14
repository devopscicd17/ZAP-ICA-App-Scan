#!/usr/bin/env bash
#
# IBM Cloud Toolchain Pipeline Wrapper for ZAP Authenticated Scan
# Can be sourced or executed directly from a pipeline stage script.
#
# Usage in .pipeline-config.yaml:
#   ica-security-scan:
#     dind: true
#     script: |
#       #!/usr/bin/env bash
#       export ICA_APP_URL="$(get_env app-url)"
#       export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
#       export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
#       cd "$WORKSPACE/$(load_repo app-repo path)"
#       source scripts/run-ica-authenticated-scan.sh
#
# Or execute directly:
#   bash scripts/run-ica-authenticated-scan.sh
#

set -euo pipefail

# =============================================================================
# Colour helpers (disabled when not a TTY)
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

# Resolve the directory containing this script (works when sourced too)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE:-$(pwd)}"

# =============================================================================
# Step 1 — Load environment configuration
# =============================================================================
setup_environment() {
    log_info "Loading ICA authenticated scan environment configuration..."

    local env_file="${SCRIPT_DIR}/zap-custom-scripts/.env.ica-authenticated-scan.sh"
    if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        log_success "Environment configuration loaded"
    else
        log_warning "Optional env file not found: ${env_file} — using defaults"
    fi

    # ------------------------------------------------------------------
    # Resolve ICA_APP_URL
    # ------------------------------------------------------------------
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        # Try IBM Toolchain pipeline variable
        if command -v get_env &> /dev/null; then
            ICA_APP_URL="$(get_env app-url "")"
            [[ -z "${ICA_APP_URL}" ]] && ICA_APP_URL="$(get_env app_url "")"
        fi
    fi
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        log_error "ICA_APP_URL is not set."
        log_error "  Option A: export ICA_APP_URL='https://your-ica-app.ibm.com'"
        log_error "  Option B: add 'app-url' secure property to your toolchain"
        return 1
    fi
    export ICA_APP_URL

    # ------------------------------------------------------------------
    # Resolve IBM_SSO_USERNAME
    # ------------------------------------------------------------------
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        if command -v get_env &> /dev/null; then
            IBM_SSO_USERNAME="$(get_env ibm-sso-username "")"
            [[ -z "${IBM_SSO_USERNAME}" ]] && IBM_SSO_USERNAME="$(get_env ibm_sso_username "")"
        fi
    fi
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        log_error "IBM_SSO_USERNAME is not set."
        log_error "  Add 'ibm-sso-username' secure property to your toolchain"
        return 1
    fi
    export IBM_SSO_USERNAME

    # ------------------------------------------------------------------
    # Resolve IBM_SSO_PASSWORD
    # ------------------------------------------------------------------
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        if command -v get_env &> /dev/null; then
            IBM_SSO_PASSWORD="$(get_env ibm-sso-password "")"
            [[ -z "${IBM_SSO_PASSWORD}" ]] && IBM_SSO_PASSWORD="$(get_env ibm_sso_password "")"
        fi
    fi
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        log_error "IBM_SSO_PASSWORD is not set."
        log_error "  Add 'ibm-sso-password' secure property to your toolchain"
        return 1
    fi
    export IBM_SSO_PASSWORD

    # Place reports inside the pipeline workspace so they are preserved
    export ZAP_REPORT_DIR="${ZAP_REPORT_DIR:-${WORKSPACE_DIR}/zap-reports}"
    mkdir -p "${ZAP_REPORT_DIR}"

    log_success "Environment setup complete"
    log_info "  Target URL : ${ICA_APP_URL}"
    log_info "  SSO User   : ${IBM_SSO_USERNAME}"
    log_info "  Report Dir : ${ZAP_REPORT_DIR}"
}

# =============================================================================
# Step 2 — Pull the ZAP Docker image
# =============================================================================
setup_zap_docker() {
    log_info "Checking Docker availability..."
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not available. Ensure the pipeline stage has 'dind: true'."
        return 1
    fi
    log_info "Docker: $(docker --version)"

    local image="${ZAP_DOCKER_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
    log_info "Pulling ZAP image: ${image}"
    if ! docker pull "${image}"; then
        log_error "Failed to pull ZAP Docker image: ${image}"
        return 1
    fi
    log_success "ZAP Docker image ready"
}

# =============================================================================
# Step 3 — Execute the full scan script
# =============================================================================
run_zap_scan() {
    local scan_script="${SCRIPT_DIR}/zap-full-scan-authenticated.sh"

    if [[ ! -f "${scan_script}" ]]; then
        log_error "Scan script not found: ${scan_script}"
        return 1
    fi

    chmod +x "${scan_script}"
    log_info "Executing: ${scan_script}"

    if bash "${scan_script}"; then
        log_success "ZAP scan completed successfully"
        return 0
    else
        log_error "ZAP scan finished with security findings or errors"
        return 1
    fi
}

# =============================================================================
# Step 4 — Collect evidence for IBM Toolchain compliance
# =============================================================================
collect_evidence() {
    log_info "Collecting scan evidence..."

    local evidence_script="${SCRIPT_DIR}/collect-zap-evidence.sh"
    if [[ -f "${evidence_script}" ]]; then
        chmod +x "${evidence_script}"
        bash "${evidence_script}" || log_warning "Evidence collection returned non-zero"
    else
        # Minimal inline evidence collection when the dedicated script is absent
        local evidence_type="${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"
        local ts
        ts="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

        # Find the newest JSON report (POSIX-compatible, no -printf)
        local json_report=""
        json_report="$(ls -t "${ZAP_REPORT_DIR}"/zap-report-*.json 2>/dev/null | head -1 || true)"

        local html_report=""
        html_report="$(ls -t "${ZAP_REPORT_DIR}"/zap-report-*.html 2>/dev/null | head -1 || true)"

        if [[ -z "${json_report}" ]]; then
            log_warning "No scan reports found in ${ZAP_REPORT_DIR} — skipping evidence"
            return 0
        fi

        local summary="${ZAP_REPORT_DIR}/evidence-summary.json"
        cat > "${summary}" <<EOF
{
  "evidence_type": "${evidence_type}",
  "scan_timestamp": "${ts}",
  "target_url": "${ICA_APP_URL}",
  "scan_type": "ZAP Full Scan - IBM SSO Authenticated",
  "authentication_method": "IBM w3id SAML2 (script-based)",
  "report_json": "$(basename "${json_report}")",
  "report_html": "$(basename "${html_report:-}")"
}
EOF
        log_success "Evidence summary written: ${summary}"

        # Save to IBM Toolchain evidence locker if running inside a pipeline
        if command -v save_artifact &> /dev/null && [[ -n "${html_report}" ]]; then
            save_artifact "zap-scan-evidence" \
                "type=${evidence_type}" \
                "path=${html_report}" \
                "summary=${summary}" \
                || log_warning "save_artifact returned non-zero (non-fatal)"
        fi
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    log_info "============================================================"
    log_info " ZAP Authenticated Scan for ICA Applications                "
    log_info " IBM Cloud Toolchain Pipeline Integration                    "
    log_info "============================================================"

    local exit_code=0

    setup_environment   || { log_error "Environment setup failed"; exit 1; }
    setup_zap_docker    || exit_code=$?

    if [[ ${exit_code} -eq 0 ]]; then
        run_zap_scan    || exit_code=$?
    fi

    # Always attempt evidence collection
    collect_evidence    || log_warning "Evidence collection failed (non-fatal)"

    if [[ ${exit_code} -eq 0 ]]; then
        log_success "============================================================"
        log_success " ZAP Authenticated Scan COMPLETED SUCCESSFULLY              "
        log_success "============================================================"
    else
        log_error "============================================================"
        log_error " ZAP Authenticated Scan FAILED — check reports               "
        log_error " Reports: ${ZAP_REPORT_DIR}                                  "
        log_error "============================================================"
    fi

    return ${exit_code}
}

# Run main only when executed directly (not sourced)
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
    exit $?
else
    main "$@"
fi

# Made with Bob
