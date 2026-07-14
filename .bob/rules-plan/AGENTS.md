# AGENTS.md — Architecture Constraints (Non-Obvious)

## Execution order is load-then-override, not override-then-load
`run-ica-authenticated-scan.sh::setup_environment()` sources `.env.ica-authenticated-scan.sh` **before** calling `get_env`. Any variable already exported by the pipeline stage (e.g. `ICA_APP_URL`) takes precedence because the `.env` file uses `${VAR:-default}` pattern. Reversing this order breaks the fallback chain.

## `SCAN_TIMESTAMP` couples `generate_reports()` and `analyze_results()`
Both functions reference `${ZAP_REPORT_DIR_ABS}/zap-report-${SCAN_TIMESTAMP}.*`. The timestamp must be set once in `set_defaults()` and exported. Any refactor that moves or re-derives the timestamp will break report analysis.

## ZAP contextId is always hardcoded to `1`
The first context ZAP creates in a fresh daemon gets `contextId=1`. All API calls use `-d "contextId=1"`. This works only because the pipeline always starts a fresh ZAP container per run. Do not attempt to look up the context ID dynamically — the ZAP context list API response format changed between versions.

## The `ibm-sso-auth.js` script is mounted read-only at `/zap/scripts/`
The Docker volume mount is `${script_dir}/zap-custom-scripts:/zap/scripts:ro`. The ZAP API `load` call references `/zap/scripts/ibm-sso-auth.js` (container path). If you add more auth scripts, they must live in `scripts/zap-custom-scripts/` to be accessible inside the container.

## ZAP API calls use `|| true` — scan cannot detect partial API failures
`_zap_api` always returns exit 0. A misconfigured auth method or failed context setup will not abort the script — the scan simply runs unauthenticated. Add explicit response parsing if API correctness needs to be validated.

## IBM Toolchain `get_env` property names: underscores only, case-sensitive
`get_env` with a dash-containing name silently returns empty string (no error, no warning). Property names are case-sensitive and must match exactly what is registered in the Toolchain Secure Properties UI. `app_url` ≠ `APP_URL`.

## Two entry points for the same scan — must stay in sync
Changes to environment variable names or defaults in `zap-full-scan-authenticated.sh` must be mirrored in `scripts/zap-automation-framework.yaml` if the AF approach is also supported. They are not automatically synchronized.
