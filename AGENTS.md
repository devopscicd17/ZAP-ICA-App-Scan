# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## What this repo is
A set of bash scripts + ZAP JavaScript for running OWASP ZAP DAST with IBM w3id SAML2 SSO against ICA-hosted apps from an IBM Cloud Toolchain pipeline.

## Critical: IBM Toolchain property names use underscores only
`get_env` silently returns empty string for any property name containing a dash.
Use `app_url`, `ibm_sso_username`, `ibm_sso_password`, `opt_in_ica_scan` — **never** `app-url`, `ibm-sso-username`, etc.

## Critical: Classic Pipeline vs Tekton — two completely different environments
- **Classic Pipeline** (Stage → Jobs tab job script): `get_env` does **not exist**. Environment properties from the "Environment properties" tab are injected as lowercase shell variables directly — `app_url` → `$app_url`, `ibm_sso_username` → `$ibm_sso_username`. There is no `.pipeline-config.yaml` involvement.
- **Tekton / One-Pipeline**: `get_env` exists. `.pipeline-config.yaml` stages run. Properties come from the pipeline configuration.
- `run-ica-authenticated-scan.sh` handles both: tries `get_env` first, falls back to the lowercase shell var injection.

## Critical: password retrieval must be wrapped in `set +x` / `set -x`
```bash
set +x
export IBM_SSO_PASSWORD="$(get_env ibm_sso_password "")"
if [[ "$PIPELINE_DEBUG" == 1 ]]; then set -x; fi
```

## Script execution chain (always follow this order)
1. `.pipeline-config.yaml` `ica-security-scan` stage validates + exports all vars via `get_env`, then calls `bash scripts/run-ica-authenticated-scan.sh`
2. `scripts/run-ica-authenticated-scan.sh` — sources `.env.ica-authenticated-scan.sh` for ZAP tuning defaults, then validates credentials were already exported by the caller; it does **not** call `get_env`
3. `scripts/zap-full-scan-authenticated.sh` — `set_defaults()` sets `SCAN_TIMESTAMP` once; every report file uses that same variable; never create a new timestamp inside `analyze_results()`
4. `scripts/collect-zap-evidence.sh` — called last; uses `ls -t … | head -1` (not `find -printf`, which is GNU-only)

## Do not `source` the scan script from the pipeline stage — use `bash`
`source scripts/run-ica-authenticated-scan.sh` runs `main()` in the current shell, which means `exit 1` inside `main()` kills the pipeline stage process before the stage's own error messages can flush. Use `bash scripts/run-ica-authenticated-scan.sh` instead.

## `PIPELINE_CONFIG_REPO_PATH` is the correct variable for `cd` in pipeline stages
`load_repo app-repo path` refers to a separate **app** repository that may not exist in a standalone scan pipeline. Use `${PIPELINE_CONFIG_REPO_PATH:-}` to locate this repo's own scripts inside `$WORKSPACE`.

## ZAP API contract
- ZAP `/core/view/alerts` returns `{"alerts":[…]}` — jq filter is `.alerts[]`, **not** `.alerts[].risk`
- Scan IDs are extracted with `grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*'`, not `jq -r '.scan'`
- `authMethodConfigParams` value must be URL-encoded: `scriptName%3DIBM-SSO-Auth%26ICA_APP_URL%3D<encoded-url>`
- ZAP Docker image: `ghcr.io/zaproxy/zaproxy:stable` (DockerHub `owasp/zap2docker-stable` is deprecated/removed)
- Auth script (`ibm-sso-auth.js`) must **return the final `HttpMessage` object**, not an `AuthenticationResult` — the latter doesn't exist in ZAP's script-based auth API

## `.env.ica-authenticated-scan.sh` rules
- Shebang is `#!/bin/false` — file must be `source`d, never executed directly
- Contains only `export VAR="${VAR:-default}"` — never `set_env` (Tekton built-in, not available when sourced locally)
- Never put credentials in this file; they come from the calling pipeline stage

## Pipeline stage requirements
- Every stage that runs Docker **must** have `dind: true`
- `opt_in_ica_scan` controls the gate; stage exits 0 silently if unset

## Local dry-run (no pipeline)
```bash
export ICA_APP_URL="https://your-app.ibm.com"
export IBM_SSO_USERNAME="user@ibm.com"
export IBM_SSO_PASSWORD="secret"
bash scripts/run-ica-authenticated-scan.sh
```

## Bash style (all scripts)
- `set -euo pipefail` at top of every script
- Logging: `log_info` / `log_success` / `log_warning` / `log_error` (defined per-script; `log_error` writes to stderr)
- Colour codes only when stdout is a TTY: `if [[ -t 1 ]]; then … else RED=''; … fi`
- Report discovery: `ls -t "${DIR}"/zap-report-*.json 2>/dev/null | head -1` (POSIX, no `find -printf`)
