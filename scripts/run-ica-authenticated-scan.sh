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
#       # IBM Toolchain Secure Properties must use underscores (not dashes)
#       export ICA_APP_URL="$(get_env app_url "")"
#       export IBM_SSO_USERNAME="$(get_env ibm_sso_username "")"
#       set +x
#       export IBM_SSO_PASSWORD="$(get_env ibm_sso_password "")"
#       set -x
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
    # ------------------------------------------------------------------
    # Load ZAP tuning defaults first. Uses ${VAR:-default} so any variable
    # already exported by the caller wins over the defaults in this file.
    # ------------------------------------------------------------------
    local env_file="${SCRIPT_DIR}/zap-custom-scripts/.env.ica-authenticated-scan.sh"
    if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        log_info "Defaults loaded from: ${env_file}"
    fi

    # ------------------------------------------------------------------
    # Resolve credentials.
    #
    # Three invocation contexts are supported, tried in priority order:
    #
    #   1. Already exported (e.g. called from .pipeline-config.yaml stage).
    #
    #   2. Tekton / One-Pipeline: get_env is available.
    #      Property names use underscores: app_url, ibm_sso_username, etc.
    #
    #   3. Classic Pipeline: get_env does NOT exist.
    #      IBM injects Stage "Environment properties" directly as shell env
    #      vars using the exact property name. app_url → $app_url, etc.
    #
    # All property names must use underscores — dashes silently return "".
    # ------------------------------------------------------------------

    # ICA_APP_URL
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        if command -v get_env &>/dev/null; then
            ICA_APP_URL="$(get_env app_url "")"
        else
            ICA_APP_URL="${app_url:-}"          # Classic Pipeline injection
        fi
        export ICA_APP_URL
    fi

    # IBM_SSO_USERNAME
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        if command -v get_env &>/dev/null; then
            IBM_SSO_USERNAME="$(get_env ibm_sso_username "")"
        else
            IBM_SSO_USERNAME="${ibm_sso_username:-}"   # Classic Pipeline injection
        fi
        export IBM_SSO_USERNAME
    fi

    # IBM_SSO_PASSWORD
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        if command -v get_env &>/dev/null; then
            IBM_SSO_PASSWORD="$(get_env ibm_sso_password "")"
        else
            IBM_SSO_PASSWORD="${ibm_sso_password:-}"   # Classic Pipeline injection
        fi
        export IBM_SSO_PASSWORD
    fi

    # Optional tuning vars — also injected directly in Classic Pipeline
    if [[ -z "${ZAP_SCAN_TIMEOUT:-}" ]]    && [[ -n "${zap_scan_timeout:-}" ]];    then export ZAP_SCAN_TIMEOUT="${zap_scan_timeout}"; fi
    if [[ -z "${ZAP_ALERT_THRESHOLD:-}" ]] && [[ -n "${zap_alert_threshold:-}" ]]; then export ZAP_ALERT_THRESHOLD="${zap_alert_threshold}"; fi
    if [[ -z "${ZAP_MAX_DEPTH:-}" ]]       && [[ -n "${zap_max_depth:-}" ]];       then export ZAP_MAX_DEPTH="${zap_max_depth}"; fi
    if [[ -z "${ZAP_DOCKER_IMAGE:-}" ]]    && [[ -n "${zap_docker_image:-}" ]];    then export ZAP_DOCKER_IMAGE="${zap_docker_image}"; fi

    # ------------------------------------------------------------------
    # Validate — all three must be set by now.
    # ------------------------------------------------------------------
    local missing=""
    [[ -z "${ICA_APP_URL:-}"      ]] && missing="${missing}\n  app_url"
    [[ -z "${IBM_SSO_USERNAME:-}" ]] && missing="${missing}\n  ibm_sso_username"
    [[ -z "${IBM_SSO_PASSWORD:-}" ]] && missing="${missing}\n  ibm_sso_password"

    if [[ -n "${missing}" ]]; then
        echo "" >&2
        echo "======================================================" >&2
        echo " ZAP Scan FAILED: Toolchain Secure Properties missing" >&2
        echo "" >&2
        echo " Add these properties in:" >&2
        echo " Toolchain UI → your Pipeline → Settings → Secure Properties" >&2
        echo "" >&2
        printf "%b\n" "${missing}" >&2
        echo "" >&2
        echo " IMPORTANT: names must use underscores, not dashes." >&2
        echo "======================================================" >&2
        return 1
    fi

    # Place reports inside the pipeline workspace so they survive the stage.
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
