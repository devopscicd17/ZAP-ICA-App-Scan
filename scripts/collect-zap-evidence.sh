#!/usr/bin/env bash
#
# collect-zap-evidence.sh
# Collect ZAP scan reports as compliance evidence for IBM Cloud Toolchain.
#
# Called automatically by run-ica-authenticated-scan.sh after each scan.
# Can also be run standalone after a scan has produced reports.
#
# Required environment variables:
#   ZAP_REPORT_DIR   — Directory containing zap-report-* files
#   ICA_APP_URL      — Target URL (used in evidence metadata)
#
# Optional:
#   ZAP_EVIDENCE_TYPE  — Evidence type string (default: com.ibm.dynamic_scan)
#   ZAP_ALERT_THRESHOLD — Used to record configured threshold in summary
#

set -euo pipefail

if [[ -t 1 ]]; then
    GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
else
    GREEN=''; YELLOW=''; BLUE=''; RED=''; NC=''
fi

log_info()    { echo -e "${BLUE}[EVIDENCE]${NC} $*"; }
log_success() { echo -e "${GREEN}[EVIDENCE]${NC} $*"; }
log_warning() { echo -e "${YELLOW}[EVIDENCE]${NC} $*" >&2; }
log_error()   { echo -e "${RED}[EVIDENCE]${NC} $*"  >&2; }

# =============================================================================
# Defaults
# =============================================================================
REPORT_DIR="${ZAP_REPORT_DIR:-./zap-reports}"
EVIDENCE_TYPE="${ZAP_EVIDENCE_TYPE:-com.ibm.dynamic_scan}"
ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
TARGET_URL="${ICA_APP_URL:-unknown}"
SCAN_TS="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

if [[ ! -d "${REPORT_DIR}" ]]; then
    log_warning "Report directory not found: ${REPORT_DIR}"
    exit 0
fi

# =============================================================================
# Locate reports — POSIX-compatible (ls -t avoids GNU-only find -printf)
# =============================================================================
html_report="$(ls -t "${REPORT_DIR}"/zap-report-*.html 2>/dev/null | head -1 || true)"
xml_report="$( ls -t "${REPORT_DIR}"/zap-report-*.xml  2>/dev/null | head -1 || true)"
json_report="$(ls -t "${REPORT_DIR}"/zap-report-*.json 2>/dev/null | head -1 || true)"
md_report="$(  ls -t "${REPORT_DIR}"/zap-report-*.md   2>/dev/null | head -1 || true)"
results_json="$(ls -t "${REPORT_DIR}"/zap-results-*.json 2>/dev/null | head -1 || true)"

if [[ -z "${json_report}" ]] && [[ -z "${html_report}" ]]; then
    log_warning "No scan reports found in ${REPORT_DIR} — nothing to collect"
    exit 0
fi

log_info "Collecting evidence from: ${REPORT_DIR}"
log_info "  HTML  : ${html_report:-<not found>}"
log_info "  XML   : ${xml_report:-<not found>}"
log_info "  JSON  : ${json_report:-<not found>}"
log_info "  MD    : ${md_report:-<not found>}"

# =============================================================================
# Parse alert counts from the results JSON (written by zap-full-scan-authenticated.sh)
# =============================================================================
HIGH=0; MED=0; LOW=0; INFO=0; PASSED="unknown"

if [[ -n "${results_json}" ]] && [[ -f "${results_json}" ]]; then
    HIGH="$(jq '.alerts.high   // 0' "${results_json}" 2>/dev/null || echo 0)"
    MED="$( jq '.alerts.medium // 0' "${results_json}" 2>/dev/null || echo 0)"
    LOW="$( jq '.alerts.low    // 0' "${results_json}" 2>/dev/null || echo 0)"
    INFO="$(jq '.alerts.informational // 0' "${results_json}" 2>/dev/null || echo 0)"
elif [[ -n "${json_report}" ]] && [[ -f "${json_report}" ]]; then
    # Fall back to parsing the raw ZAP alerts JSON
    HIGH="$(jq '[.alerts[] | select(.risk=="High")]         | length' "${json_report}" 2>/dev/null || echo 0)"
    MED="$( jq '[.alerts[] | select(.risk=="Medium")]       | length' "${json_report}" 2>/dev/null || echo 0)"
    LOW="$( jq '[.alerts[] | select(.risk=="Low")]          | length' "${json_report}" 2>/dev/null || echo 0)"
    INFO="$(jq '[.alerts[] | select(.risk=="Informational")]| length' "${json_report}" 2>/dev/null || echo 0)"
fi

# Determine overall pass/fail based on threshold
case "${ALERT_THRESHOLD^^}" in
    HIGH)         [[ ${HIGH} -eq 0 ]] && PASSED="true" || PASSED="false" ;;
    MEDIUM)       { [[ ${HIGH} -eq 0 ]] && [[ ${MED} -eq 0 ]]; } && PASSED="true" || PASSED="false" ;;
    LOW)          { [[ ${HIGH} -eq 0 ]] && [[ ${MED} -eq 0 ]] && [[ ${LOW} -eq 0 ]]; } && PASSED="true" || PASSED="false" ;;
    INFORMATIONAL){ [[ ${HIGH} -eq 0 ]] && [[ ${MED} -eq 0 ]] && [[ ${LOW} -eq 0 ]] && [[ ${INFO} -eq 0 ]]; } && PASSED="true" || PASSED="false" ;;
    *)             PASSED="unknown" ;;
esac

log_info "Alert summary — High: ${HIGH}, Medium: ${MED}, Low: ${LOW}, Info: ${INFO}"
log_info "Threshold: ${ALERT_THRESHOLD} — Passed: ${PASSED}"

# =============================================================================
# Write evidence summary JSON
# =============================================================================
SUMMARY_FILE="${REPORT_DIR}/evidence-summary.json"

cat > "${SUMMARY_FILE}" <<EOF
{
  "evidence_type": "${EVIDENCE_TYPE}",
  "scan_timestamp": "${SCAN_TS}",
  "target_url": "${TARGET_URL}",
  "scan_type": "ZAP Full Scan — IBM SSO Authenticated (ICA)",
  "authentication_method": "IBM w3id SAML2 POST-binding (script-based)",
  "alert_threshold": "${ALERT_THRESHOLD}",
  "passed": ${PASSED},
  "alerts": {
    "high": ${HIGH},
    "medium": ${MED},
    "low": ${LOW},
    "informational": ${INFO}
  },
  "reports": {
    "html":  "$(basename "${html_report:-}")",
    "xml":   "$(basename "${xml_report:-}")",
    "json":  "$(basename "${json_report:-}")",
    "md":    "$(basename "${md_report:-}")"
  }
}
EOF

log_success "Evidence summary written: ${SUMMARY_FILE}"

# =============================================================================
# Save evidence to IBM Toolchain locker (only available inside a pipeline)
# =============================================================================
if command -v save_artifact &> /dev/null; then
    log_info "Saving evidence to IBM Toolchain locker..."

    # Primary evidence — HTML report
    if [[ -n "${html_report}" ]] && [[ -f "${html_report}" ]]; then
        save_artifact "zap-scan-report-html" \
            "type=${EVIDENCE_TYPE}" \
            "path=${html_report}" \
            || log_warning "save_artifact (HTML) returned non-zero"
    fi

    # Machine-readable evidence — JSON results summary
    save_artifact "zap-scan-evidence-summary" \
        "type=${EVIDENCE_TYPE}" \
        "path=${SUMMARY_FILE}" \
        || log_warning "save_artifact (summary) returned non-zero"

    # XML report — for SonarQube / DefectDojo
    if [[ -n "${xml_report}" ]] && [[ -f "${xml_report}" ]]; then
        save_artifact "zap-scan-report-xml" \
            "type=${EVIDENCE_TYPE}" \
            "path=${xml_report}" \
            || log_warning "save_artifact (XML) returned non-zero"
    fi

    log_success "Evidence saved to IBM Toolchain locker"
else
    log_info "Not running inside IBM Toolchain — evidence files saved locally only"
fi

# =============================================================================
# Print final evidence location
# =============================================================================
log_success "Evidence collection complete"
log_info "Files in ${REPORT_DIR}:"
ls -lh "${REPORT_DIR}" 2>/dev/null || true

# Made with Bob
