# AGENTS.md — Coding Rules (Non-Obvious)

## Never use dashes in `get_env` calls — they silently return empty
All IBM Toolchain property lookups must use underscores: `get_env app_url ""`, `get_env ibm_sso_username ""`, etc.

## `SCAN_TIMESTAMP` is set once in `set_defaults()` and shared globally
Do not introduce a second `timestamp` variable anywhere else in `zap-full-scan-authenticated.sh` — `generate_reports()` and `analyze_results()` both depend on the same `SCAN_TIMESTAMP` value to reference the same files.

## ZAP auth script returns `HttpMessage`, not `AuthenticationResult`
`ibm-sso-auth.js` must return the last `HttpMessage` from `authenticate()`. There is no `AuthenticationResult` class in ZAP's scripted auth API. Returning `null` signals auth failure.

## `authMethodConfigParams` must be double-URL-encoded
The config param string sent to ZAP's `/authentication/action/setAuthenticationMethod/` must have its `=` and `&` percent-encoded: `scriptName%3DIBM-SSO-Auth%26ICA_APP_URL%3D<url-encoded-url>`.

## Credential encoding in `setAuthenticationCredentials`
Username and password must be individually URL-encoded with `python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))"` before embedding in the config-params string — raw values break on `@`, `+`, and special chars.

## `forcedUser` mode must be enabled after creating the user
Call both `/JSON/forcedUser/action/setForcedUser/` and `/JSON/forcedUser/action/setForcedUserModeEnabled/` — without this, spider and active scan still run unauthenticated even though a user exists in the context.

## `.env.ica-authenticated-scan.sh` must never be executed, only sourced
The shebang `#!/bin/false` enforces this. Do not add `set_env` calls inside it — `set_env` is a Tekton pipeline built-in unavailable outside that environment.

## Report file discovery — no `find -printf`
The pipeline base image is UBI/Alpine; `find -printf` is GNU-only and will fail silently. Always use `ls -t "${DIR}"/pattern 2>/dev/null | head -1`.

## ZAP API helper `_zap_api` swallows errors with `|| true`
All ZAP API calls are non-fatal by design. If you need to gate on a specific API response, parse the output explicitly rather than relying on exit code.
