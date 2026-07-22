# AGENTS.md

This file provides guidance to agents working with this repository.

## What this repo is
Bash scripts + ZAP JavaScript for running OWASP ZAP DAST with IBM w3id SAML2 SSO against ICA-hosted apps from an IBM Cloud Toolchain **Classic Pipeline**.

---

## Pipeline runner: Custom Docker Image (Classic Pipeline)

The Classic Pipeline job type is **Custom Docker Image** with image `ghcr.io/zaproxy/zaproxy:stable`.
The job runs **inside** the ZAP container. `zap.sh` is at `/zap/zap.sh`.
There is **no Docker daemon** — the script calls `zap.sh -cmd -autorun` directly.
The automation plan YAML is generated at runtime with credentials substituted in
(ZAP's own `${VAR}` substitution is unreliable across versions — never rely on it).

**Build script (Jobs tab) must be exactly:**
```bash
#!/bin/bash
set -e
bash scripts/run-ica-authenticated-scan.sh
```

**ZAP-container-specific constraints:**
- The `zap` user can only write to `/zap/wrk` — `mkdir ./zap-reports` fails with permission denied.
- ZAP prepends `/zap/` to any relative path in the automation plan — `./zap-reports/plan.yaml` becomes `/zap/./zap-reports/plan.yaml` (not found). Always use absolute path `/zap/wrk` for `ZAP_REPORT_DIR`.
- The generated plan is written to `/zap/wrk/automation-plan.yaml` (chmod 600 — it contains credentials).
- The **workspace directory** (`/workspace/<uuid>/`) is also **read-only** for the `zap` user — `mkdir` inside it fails with "Permission denied". Use `mkdir -p ... 2>/dev/null` with an `if` guard and silently skip the copy if it fails.
- **IBM Toolchain web UI HTML-encodes property values** — `app_url` set via the UI arrives as `https://...?foo=1&amp;bar=2` (literal `&amp;`). Always decode HTML entities after resolving `ICA_APP_URL`. `run-ica-authenticated-scan.sh` does this with bash string substitution; `ibm-sso-auth.js` does it with `_htmlDecode()`.

---

## ZAP Automation Framework schema facts (do not guess — these are verified)

### `script` job parameters (confirmed from live ZAP runs)
```yaml
- type: script
  parameters:
    action: add            # "add" to load a new script
    type: authentication   # script category
    engine: "ECMAScript : Graal.js"   # see engine names below
    name: "IBM-SSO-Auth"              # logical name
    source: "/absolute/path/to/ibm-sso-auth.js"   # ← confirmed key is `source:`
    # NOT `script:`, NOT `scriptPath:`, NOT `fileName:`
```
**However: this job is NOT needed.** The context `authentication.parameters.script` (file path)
causes ZAP to load and register the script automatically at context-validation time, before any
job runs. Adding a separate `script` job causes double-loading and potential conflicts.

### Context authentication parameters (confirmed from live ZAP runs)
When `authentication.method: script`, the `parameters` block must contain:
```yaml
parameters:
  script: "/absolute/path/to/ibm-sso-auth.js"   # ← FILE PATH (not a logical name)
  # ZAP resolves relative paths under /zap/wrk — MUST use absolute path
  # NOT `scriptName:` (unrecognised)
  # "script: IBM-SSO-Auth" is WRONG — ZAP tries to open /zap/wrk/IBM-SSO-Auth as a file
```
ZAP validates the `script` field as a readable file path at plan-load time (before jobs run).
The error text `Neither 'scriptInline' nor 'script' specified` names the two valid field options.

### Script engine names
- **ZAP 2.14+ (`ghcr.io/zaproxy/zaproxy:stable`)**: `"ECMAScript : Graal.js"` — GraalVM JS replaces Nashorn.
- **ZAP 2.13 and earlier**: `"Oracle Nashorn"`.
- `ibm-sso-auth.js` is fully compatible with both Graal.js and Nashorn.

### `activeScan` job duration parameter
- `maxScanDurationInMins` — **not** `maxDuration` (which is the spider/spiderAjax parameter).

### `spider` job duration parameter
- `maxDuration` — minutes. Correct for the spider job.

### YAML regex escaping for `loggedInRegex` / `loggedOutRegex`
- Use **single-quoted YAML strings** for regex patterns containing `\Q…\E` (Java Pattern.quote syntax).
- Double-quoted YAML strings treat `\Q` as unknown escape → YAML parse error.
- Correct: `loggedInRegex: '\QLogout\E|\Qlogout\E'`
- Wrong:   `loggedInRegex: "\\QLogout\\E"` (double-escaped, fragile) or `"\\QLogout\E"` (parse error).

### YAML regex for file extension exclusions
- Use `.*[.]pdf$` not `.*\.pdf$` — the backslash-dot is an unknown escape in double-quoted YAML.
- In bash heredocs, `$` at end of line must be escaped as `\$` to prevent shell expansion.

---

## IBM Toolchain: Critical property naming rules

- Property names **must use underscores only** — dashes silently return empty string from `get_env`.
- Required names: `app_url`, `ibm_sso_username`, `ibm_sso_password`, `opt_in_ica_scan`.
- **Never use**: `app-url`, `ibm-sso-username`, etc.

---

## Classic Pipeline vs Tekton — two completely different environments

| Feature | Classic Pipeline | Tekton / One-Pipeline |
|---------|-----------------|----------------------|
| `get_env` available | ❌ No | ✅ Yes |
| `.pipeline-config.yaml` used | ❌ No | ✅ Yes |
| Env properties injected as | Lowercase shell vars | Tekton params / `get_env` |
| Example: `app_url` property | `$app_url` shell var | `$(get_env app_url "")` |
| Custom Docker Image job | ✅ Native | N/A (use `image:` in config) |

`run-ica-authenticated-scan.sh` handles **both**: tries `get_env` first, falls back to the lowercase shell variable injection.

---

## opt_in gate

`opt_in_ica_scan` environment property controls whether the scan runs:
- **Classic Pipeline**: `check_opt_in()` in `run-ica-authenticated-scan.sh` — exits 0 silently if not set.
- **Tekton**: `.pipeline-config.yaml` `ica-security-scan` stage checks `get_env opt_in_ica_scan ""` before calling the script.
- If `ICA_APP_URL` is already exported (Tekton path), the gate is bypassed (Tekton already gated).

---

## Password / credential safety rules

- Never `set -x` during password retrieval. Wrap in `set +x` / `if [[ "$PIPELINE_DEBUG" == 1 ]]; then set -x; fi`.
- The generated plan file `/zap/wrk/automation-plan.yaml` contains credentials — always `chmod 600` after writing.
- Never `source` the scan script from a pipeline stage — use `bash`. `source` means `exit 1` inside `main()` kills the stage process before its own error messages can flush.

---

## Script execution chain

1. **Classic Pipeline**: Jobs tab build script → `bash scripts/run-ica-authenticated-scan.sh`
2. **Tekton**: `.pipeline-config.yaml` `ica-security-scan` stage validates + exports via `get_env` → `bash scripts/run-ica-authenticated-scan.sh`
3. `run-ica-authenticated-scan.sh`:
   - `check_opt_in()` — gate
   - `setup_environment()` — sources `.env.ica-authenticated-scan.sh`, resolves credentials
   - `find_zap()` — locates `/zap/zap.sh`
   - `generate_automation_plan()` — writes `/zap/wrk/automation-plan.yaml` (chmod 600)
   - `run_zap_scan()` — calls `/zap/zap.sh -cmd -autorun /zap/wrk/automation-plan.yaml`
   - `collect_evidence()` — copies reports to `$WORKSPACE/zap-reports`
   - `analyze_results()` — parses JSON report, fails on threshold breach

---

## `ibm-sso-auth.js` — critical implementation rules

- **Root cause of NPE (confirmed)**: In GraalVM JS (ZAP 2.14+), `HttpRequestHeader.GET`, `.POST`, and `.HTTP11` are Java `String` objects. The 3-arg constructor calls `version.toUpperCase()` on them and NPEs. Use plain JS string literals `"GET"`, `"POST"`, `"HTTP/1.1"` — never Java constants.
- **`_buildMsg(method, url)`** is the only safe way to create messages: `new HttpRequestHeader(String(method), uri, "HTTP/1.1")` → `new HttpMessage(header)`. Never `helper.prepareMessage()`.
- **ZAP double-encodes `&` in paramsValues**: read `ICA_APP_URL` from `java.lang.System.getenv("ICA_APP_URL")` first — the OS env has the clean value.
- **Wrap `sendAndReceive` in try/catch** — ZAP's response parser can also NPE on redirect responses.
- **Two IBM SSO flows** — `ibm-sso-auth.js` auto-detects:
  - **Flow A (IBM Cloud OIDC / prepiam.ice.ibmcloud.com)**: app returns HTTP 200 with a **JavaScript redirect** (not a 302) — `window.location=`, `location.replace()`, or `<meta http-equiv=refresh>`. `_extractJsRedirect(body)` parses all three patterns; if found and matches `prepiam`/`ibmcloud.com`, routes to `_authenticateOIDC()` which fetches the OIDC authorize endpoint, follows redirects to the HTML login form, POSTs credentials plus all hidden fields (CSRF/state tokens), then follows the post-login redirect. A secondary JS redirect hop is handled in `_authenticateOIDC` itself.
  - **Flow B (w3id SAML2)**: app redirects to `w3id.sso.ibm.com`, SAMLRequest in hidden field, POST to IdP, SAMLResponse to SP ACS.
- **`_extractJsRedirect(html)`** — defined at line 412 in `ibm-sso-auth.js`. Checks `window.location`, `location.replace`, `location.href`, and `meta[http-equiv=refresh]`. Returns only full `https?://` URLs after `_htmlDecode`. Called in `authenticate()` (line 89) and as a fallback in `_authenticateOIDC()` (line 147) to follow a second-hop JS redirect when the OIDC authorize URL itself returns another JS page.
- **DNS resolution**: the ZAP pipeline worker may not resolve `w3id.sso.ibm.com` (external IBM network). Apps using OIDC flow through `prepiam.ice.ibmcloud.com` may also be unreachable if they're on IBM internal network.

---

## ZAP API contract

- ZAP `/core/view/alerts` returns `{"alerts":[…]}` — jq filter is `.alerts[]`, **not** `.alerts[].risk`.
- Scan IDs: `grep -o '"scan":"[0-9]*"' | grep -o '[0-9]*'`, not `jq -r '.scan'`.
- `authMethodConfigParams` value must be URL-encoded: `scriptName%3DIBM-SSO-Auth%26ICA_APP_URL%3D<encoded-url>`.
- ZAP Docker image: `ghcr.io/zaproxy/zaproxy:stable` (DockerHub `owasp/zap2docker-stable` is deprecated/removed).
- Auth script (`ibm-sso-auth.js`) must **return the final `HttpMessage` object** — never `null`. ZAP treats null as a hard auth failure and may abort the scan.

---

## `.env.ica-authenticated-scan.sh` rules

- Shebang is `#!/bin/false` — must be `source`d, never executed directly.
- Contains only `export VAR="${VAR:-default}"` — never `set_env` (Tekton built-in, not available when sourced locally).
- Never put credentials in this file — they come from the calling pipeline stage.
- `ZAP_REPORT_DIR` defaults to `/zap/wrk`. `run-ica-authenticated-scan.sh` forces this value when `/zap/zap.sh` is detected.

---

## Tekton stage requirements (`.pipeline-config.yaml`)

- `dind: true` is required for stages that run Docker inside the pipeline agent.
- The `ica-security-scan` stage uses `dind: true` only for the Tekton path (not needed for Classic Pipeline Custom Docker Image).

---

## Local dry-run (no pipeline)
```bash
export ICA_APP_URL="https://your-app.ibm.com"
export IBM_SSO_USERNAME="user@ibm.com"
export IBM_SSO_PASSWORD="secret"
export opt_in_ica_scan="true"
bash scripts/run-ica-authenticated-scan.sh
```

---

## Bash style (all scripts)

- `set -euo pipefail` at top of every script.
- Logging: `log_info` / `log_success` / `log_warning` / `log_error` (defined per-script; `log_error` writes to stderr).
- Colour codes only when stdout is a TTY: `if [[ -t 1 ]]; then … else RED=''; … fi`.
- Report discovery: `ls -t "${DIR}"/zap-report-*.json 2>/dev/null | head -1` (POSIX; `find -printf` is GNU-only).
