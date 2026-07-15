#!/usr/bin/env bash
#
# IBM Cloud Toolchain — ZAP Authenticated Scan for ICA Applications
#
# Designed for the Classic Pipeline "Custom Docker Image" builder type using
# ghcr.io/zaproxy/zaproxy:stable as the job image.  ZAP's zap.sh is called
# directly — no Docker-in-Docker required.
#
# The script also works when called from a Tekton stage (where credentials
# are already exported) or locally (where they are set in the environment).
#
# Pipeline "Environment properties" required (underscores only):
#   app_url            — Target ICA application URL
#   ibm_sso_username   — IBM w3id email address
#   ibm_sso_password   — IBM w3id password (use Secure type)
#
# Optional properties:
#   zap_scan_timeout   — Active scan timeout in minutes (default: 60)
#   zap_alert_threshold — HIGH | MEDIUM | LOW              (default: MEDIUM)
#   zap_max_depth      — Spider crawl depth               (default: 5)
#

set -euo pipefail

# =============================================================================
# Colour helpers — disabled when not a TTY (pipeline log output)
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

# Directory containing this script (works whether called or sourced)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKSPACE_DIR="${WORKSPACE:-$(pwd)}"

# =============================================================================
# Step 1 — Resolve and validate credentials
# =============================================================================
setup_environment() {
    # Load ZAP tuning defaults (${VAR:-default} so caller-exported vars win).
    local env_file="${SCRIPT_DIR}/zap-custom-scripts/.env.ica-authenticated-scan.sh"
    if [[ -f "${env_file}" ]]; then
        # shellcheck disable=SC1090
        source "${env_file}"
        log_info "Defaults loaded from: ${env_file}"
    fi

    # ------------------------------------------------------------------
    # Resolve credentials — three contexts in priority order:
    #
    #   1. Already exported by caller (Tekton stage / local run).
    #   2. Tekton get_env built-in (One-Pipeline).
    #   3. Classic Pipeline direct injection: property name == env var name.
    #      e.g. "app_url" property → $app_url shell variable.
    # ------------------------------------------------------------------

    # ICA_APP_URL
    if [[ -z "${ICA_APP_URL:-}" ]]; then
        if command -v get_env &>/dev/null; then
            ICA_APP_URL="$(get_env app_url "")"
        else
            ICA_APP_URL="${app_url:-}"
        fi
        export ICA_APP_URL
    fi

    # IBM_SSO_USERNAME
    if [[ -z "${IBM_SSO_USERNAME:-}" ]]; then
        if command -v get_env &>/dev/null; then
            IBM_SSO_USERNAME="$(get_env ibm_sso_username "")"
        else
            IBM_SSO_USERNAME="${ibm_sso_username:-}"
        fi
        export IBM_SSO_USERNAME
    fi

    # IBM_SSO_PASSWORD
    if [[ -z "${IBM_SSO_PASSWORD:-}" ]]; then
        if command -v get_env &>/dev/null; then
            IBM_SSO_PASSWORD="$(get_env ibm_sso_password "")"
        else
            IBM_SSO_PASSWORD="${ibm_sso_password:-}"
        fi
        export IBM_SSO_PASSWORD
    fi

    # Optional tuning — pick up Classic Pipeline injected vars if not already set
    if [[ -z "${ZAP_SCAN_TIMEOUT:-}" ]]    && [[ -n "${zap_scan_timeout:-}" ]];    then export ZAP_SCAN_TIMEOUT="${zap_scan_timeout}"; fi
    if [[ -z "${ZAP_ALERT_THRESHOLD:-}" ]] && [[ -n "${zap_alert_threshold:-}" ]]; then export ZAP_ALERT_THRESHOLD="${zap_alert_threshold}"; fi
    if [[ -z "${ZAP_MAX_DEPTH:-}" ]]       && [[ -n "${zap_max_depth:-}" ]];       then export ZAP_MAX_DEPTH="${zap_max_depth}"; fi

    # Apply defaults for tuning vars
    export ZAP_SCAN_TIMEOUT="${ZAP_SCAN_TIMEOUT:-60}"
    export ZAP_ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
    export ZAP_MAX_DEPTH="${ZAP_MAX_DEPTH:-5}"

    # Validate
    local missing=""
    [[ -z "${ICA_APP_URL:-}"      ]] && missing="${missing}\n  app_url          — ICA application URL"
    [[ -z "${IBM_SSO_USERNAME:-}" ]] && missing="${missing}\n  ibm_sso_username — IBM w3id email"
    [[ -z "${IBM_SSO_PASSWORD:-}" ]] && missing="${missing}\n  ibm_sso_password — IBM w3id password"

    if [[ -n "${missing}" ]]; then
        echo "" >&2
        echo "======================================================" >&2
        echo " ZAP Scan FAILED: Toolchain properties not set" >&2
        echo "" >&2
        echo " Add these in Toolchain → Pipeline → Stage →" >&2
        echo " 'Environment properties' tab (use underscores):" >&2
        printf "%b\n" "${missing}" >&2
        echo "======================================================" >&2
        return 1
    fi

    # Report directory.
    # IMPORTANT: When running inside the ZAP Docker image (Custom Docker Image
    # builder), the container runs as user 'zap' which can only write to /zap/wrk.
    # ZAP also prepends /zap/ to any relative path in the automation plan.
    # Use /zap/wrk as the canonical writable directory.
    export ZAP_REPORT_DIR="${ZAP_REPORT_DIR:-/zap/wrk}"
    mkdir -p "${ZAP_REPORT_DIR}" 2>/dev/null || true

    log_success "Environment setup complete"
    log_info "  Target URL       : ${ICA_APP_URL}"
    log_info "  SSO User         : ${IBM_SSO_USERNAME}"
    log_info "  Alert Threshold  : ${ZAP_ALERT_THRESHOLD}"
    log_info "  Scan Timeout     : ${ZAP_SCAN_TIMEOUT} min"
    log_info "  Report Dir       : ${ZAP_REPORT_DIR}"
}

# =============================================================================
# Step 2 — Locate zap.sh
# =============================================================================
find_zap() {
    # When running inside ghcr.io/zaproxy/zaproxy:stable the binary is at /zap/zap.sh
    for candidate in /zap/zap.sh "$(command -v zap.sh 2>/dev/null || true)"; do
        if [[ -n "${candidate}" && -x "${candidate}" ]]; then
            ZAP_SH="${candidate}"
            log_success "ZAP found: ${ZAP_SH}"
            return 0
        fi
    done

    log_error "zap.sh not found. This script must run inside the ZAP Docker image."
    log_error ""
    log_error "In your Classic Pipeline job:"
    log_error "  Builder type    : Custom Docker Image"
    log_error "  Docker image    : ghcr.io/zaproxy/zaproxy:stable"
    return 1
}

# =============================================================================
# Step 3 — Generate the ZAP Automation Framework plan with actual values
# =============================================================================
generate_automation_plan() {
    local plan_dir="${ZAP_REPORT_DIR}"
    local plan_file="${plan_dir}/automation-plan.yaml"
    local auth_script="${SCRIPT_DIR}/zap-custom-scripts/ibm-sso-auth.js"

    if [[ ! -f "${auth_script}" ]]; then
        log_error "IBM SSO auth script not found: ${auth_script}"
        return 1
    fi

    log_info "Generating automation plan..."

    # ZAP reads ${VAR} substitution only in some fields — safest to write the
    # actual values directly into the plan file so nothing depends on ZAP's
    # variable substitution support.
    cat > "${plan_file}" <<YAML
---
env:
  contexts:
    - name: ICA-App-Context
      urls:
        - "${ICA_APP_URL}"
      includePaths:
        - "${ICA_APP_URL}.*"
      excludePaths:
        - ".*logout.*"
        - ".*signout.*"
        - ".*sign-out.*"
        - ".*\\.pdf\$"
        - ".*\\.zip\$"
      authentication:
        method: "script"
        parameters:
          scriptName: "IBM-SSO-Auth"
          scriptEngine: "Oracle Nashorn"
          ICA_APP_URL: "${ICA_APP_URL}"
          IBM_SSO_LOGIN_URL: "${IBM_SSO_LOGIN_URL:-https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20}"
        verification:
          method: "response"
          loggedInRegex: "\\\\QLogout\\\\E|\\\\Qlogout\\\\E|\\\\QSign Out\\\\E"
          loggedOutRegex: "\\\\QLogin\\\\E|\\\\Qlogin\\\\E|\\\\Qw3id.sso.ibm.com\\\\E"
          pollFrequency: 60
          pollUnits: "requests"
      users:
        - name: "IBMSSOUser"
          credentials:
            username: "${IBM_SSO_USERNAME}"
            password: "${IBM_SSO_PASSWORD}"
  parameters:
    failOnError: true
    failOnWarning: false
    progressToStdout: true

jobs:

  - type: script
    name: "Load IBM SSO Auth Script"
    parameters:
      action: add
      type: authentication
      engine: "Oracle Nashorn"
      name: "IBM-SSO-Auth"
      fileName: "${auth_script}"

  - type: spider
    name: "Spider ICA Application"
    parameters:
      context: ICA-App-Context
      user: IBMSSOUser
      maxDuration: $(( ZAP_SCAN_TIMEOUT / 2 ))
      maxDepth: ${ZAP_MAX_DEPTH}
      maxChildren: 0
      acceptCookies: true
      threadCount: 2

  - type: passiveScan-wait
    name: "Wait for Passive Scan"
    parameters:
      maxDuration: 10

  - type: activeScan
    name: "Active Scan ICA Application"
    parameters:
      context: ICA-App-Context
      user: IBMSSOUser
      maxDuration: ${ZAP_SCAN_TIMEOUT}
      maxRuleDurationInMins: 5
      threadPerHost: 2
      handleAntiCSRFTokens: true

  - type: report
    name: "HTML Report"
    parameters:
      template: traditional-html-plus
      reportDir: "${ZAP_REPORT_DIR}"
      reportFile: zap-report-ica.html
      reportTitle: "ZAP Security Scan — ICA Application"

  - type: report
    name: "XML Report"
    parameters:
      template: traditional-xml
      reportDir: "${ZAP_REPORT_DIR}"
      reportFile: zap-report-ica.xml
      reportTitle: "ZAP Security Scan — ICA Application"

  - type: report
    name: "JSON Report"
    parameters:
      template: traditional-json
      reportDir: "${ZAP_REPORT_DIR}"
      reportFile: zap-report-ica.json
      reportTitle: "ZAP Security Scan — ICA Application"
YAML

    log_success "Automation plan written: ${plan_file}"
    ZAP_PLAN_FILE="${plan_file}"
    export ZAP_PLAN_FILE
}

# =============================================================================
# Step 4 — Run ZAP via the Automation Framework CLI
# =============================================================================
run_zap_scan() {
    log_info "Starting ZAP Automation Framework scan..."
    log_info "  Plan     : ${ZAP_PLAN_FILE}"
    log_info "  ZAP      : ${ZAP_SH}"

    # ZAP writes its own logs to stdout; capture exit code separately
    local zap_exit=0
    "${ZAP_SH}" -cmd \
        -autorun "${ZAP_PLAN_FILE}" \
        -config api.disablekey=true \
        2>&1 || zap_exit=$?

    if [[ ${zap_exit} -ne 0 ]]; then
        log_warning "ZAP exited with code ${zap_exit} (may indicate alerts found or scan error)"
    else
        log_success "ZAP scan completed (exit 0)"
    fi

    return ${zap_exit}
}

# =============================================================================
# Step 5 — Parse JSON report and check against alert threshold
# =============================================================================
analyze_results() {
    local json_report="${ZAP_REPORT_DIR}/zap-report-ica.json"

    if [[ ! -f "${json_report}" ]]; then
        log_error "JSON report not found: ${json_report}"
        log_error "ZAP may have failed before generating reports — check output above."
        return 1
    fi

    # ZAP JSON report root key is "site" array in traditional-json template
    # Try both .site[].alerts[] (older) and .alerts[] (newer) structures
    local high med low info
    high="$(jq '[.. | objects | select(has("riskdesc")) | select(.riskdesc | startswith("High"))]   | length' "${json_report}" 2>/dev/null || echo 0)"
    med="$( jq '[.. | objects | select(has("riskdesc")) | select(.riskdesc | startswith("Medium"))] | length' "${json_report}" 2>/dev/null || echo 0)"
    low="$( jq '[.. | objects | select(has("riskdesc")) | select(.riskdesc | startswith("Low"))]    | length' "${json_report}" 2>/dev/null || echo 0)"
    info="$(jq '[.. | objects | select(has("riskdesc")) | select(.riskdesc | startswith("Informational"))] | length' "${json_report}" 2>/dev/null || echo 0)"

    log_info "Scan Results:"
    log_info "  High          : ${high}"
    log_info "  Medium        : ${med}"
    log_info "  Low           : ${low}"
    log_info "  Informational : ${info}"
    log_info "  Threshold     : ${ZAP_ALERT_THRESHOLD}"

    # Write machine-readable summary
    cat > "${ZAP_REPORT_DIR}/zap-results-summary.json" <<EOF
{
  "scan_timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "target_url": "${ICA_APP_URL}",
  "alert_threshold": "${ZAP_ALERT_THRESHOLD}",
  "alerts": { "high": ${high}, "medium": ${med}, "low": ${low}, "informational": ${info} }
}
EOF

    local fail=false
    case "${ZAP_ALERT_THRESHOLD^^}" in
        HIGH)         [[ ${high} -gt 0 ]]                          && fail=true ;;
        MEDIUM)       [[ ${high} -gt 0 || ${med} -gt 0 ]]          && fail=true ;;
        LOW)          [[ ${high} -gt 0 || ${med} -gt 0 || ${low} -gt 0 ]] && fail=true ;;
        INFORMATIONAL)[[ ${high} -gt 0 || ${med} -gt 0 || ${low} -gt 0 || ${info} -gt 0 ]] && fail=true ;;
    esac

    if [[ "${fail}" == "true" ]]; then
        log_error "FAIL: alerts found above ${ZAP_ALERT_THRESHOLD} threshold"
        return 1
    fi

    log_success "PASS: no alerts above ${ZAP_ALERT_THRESHOLD} threshold"
    return 0
}

# =============================================================================
# Step 6 — Collect evidence for IBM Toolchain compliance locker
# =============================================================================
collect_evidence() {
    log_info "Collecting scan evidence..."

    local html="${ZAP_REPORT_DIR}/zap-report-ica.html"
    local summary="${ZAP_REPORT_DIR}/zap-results-summary.json"

    if [[ ! -f "${html}" ]]; then
        log_warning "No HTML report found — evidence collection skipped"
        log_info "Reports directory contents:"
        ls -lh "${ZAP_REPORT_DIR}"/ 2>/dev/null || true
        return 0
    fi

    log_success "Reports available in: ${ZAP_REPORT_DIR}"
    ls -lh "${ZAP_REPORT_DIR}"/ 2>/dev/null || true

    # Copy reports from /zap/wrk to the pipeline workspace so the Toolchain
    # artifact uploader can find them outside the container filesystem.
    if [[ "${ZAP_REPORT_DIR}" == /zap/wrk* ]] && [[ -d "${WORKSPACE_DIR}" ]]; then
        local ws_reports="${WORKSPACE_DIR}/zap-reports"
        mkdir -p "${ws_reports}"
        cp -f "${ZAP_REPORT_DIR}"/zap-report-ica.* "${ws_reports}/" 2>/dev/null || true
        [[ -f "${summary}" ]] && cp -f "${summary}" "${ws_reports}/" 2>/dev/null || true
        log_info "Reports copied to workspace: ${ws_reports}"
        # Point html/summary at copied paths for save_artifact
        html="${ws_reports}/zap-report-ica.html"
        summary="${ws_reports}/zap-results-summary.json"
    fi

    # Save to IBM Toolchain evidence locker when running in Tekton
    if command -v save_artifact &>/dev/null; then
        save_artifact "zap-scan-report" \
            "type=com.ibm.dynamic_scan" \
            "path=${html}" \
            || log_warning "save_artifact returned non-zero (non-fatal)"

        if [[ -f "${summary}" ]]; then
            save_artifact "zap-scan-summary" \
                "type=com.ibm.dynamic_scan" \
                "path=${summary}" \
                || log_warning "save_artifact summary returned non-zero (non-fatal)"
        fi
    fi
}

# =============================================================================
# Main
# =============================================================================
main() {
    log_info "============================================================"
    log_info " ZAP Authenticated Scan for ICA Applications                "
    log_info " IBM Cloud Toolchain — Classic Pipeline                     "
    log_info "============================================================"

    local exit_code=0

    setup_environment       || { log_error "Environment setup failed"; exit 1; }
    find_zap                || { log_error "ZAP not found"; exit 1; }
    generate_automation_plan || { log_error "Failed to generate automation plan"; exit 1; }
    run_zap_scan            || exit_code=$?
    collect_evidence        || log_warning "Evidence collection failed (non-fatal)"

    # Always analyse results — even if ZAP returned non-zero (may just mean alerts found)
    if [[ -f "${ZAP_REPORT_DIR}/zap-report-ica.json" ]]; then
        analyze_results || exit_code=1
    fi

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

# Run main — whether called directly or via bash/source
main "$@"

# Made with Bob
