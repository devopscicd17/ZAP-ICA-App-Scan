# AGENTS.md — Documentation Context (Non-Obvious)

## Two scan approaches exist — only one is complete
`scripts/zap-full-scan-authenticated.sh` is the primary scan implementation (daemon mode, ZAP REST API, step-by-step).
`scripts/zap-automation-framework.yaml` is an alternative single-container approach (ZAP 2.12+ `-cmd -autorun`) — it is **not** called by the pipeline; it must be invoked manually via `docker run`.

## `.env.ica-authenticated-scan.sh` sets defaults only — it is NOT the source of credentials
Credentials (`ICA_APP_URL`, `IBM_SSO_USERNAME`, `IBM_SSO_PASSWORD`) are intentionally commented out in that file. They must come from the pipeline stage via `get_env`. The file only sets `ZAP_*` tuning defaults.

## `examples/example-pipeline-config.yaml` is a reference, not active config
It is not referenced by the running pipeline. The live config is `.pipeline-config.yaml` at the repo root.

## `ibm-sso-auth.js` is a ZAP Nashorn script, not a Node.js script
It uses Java interop (`Java.type`, `java.net.URLEncoder.encode`, `java.lang.System.getenv`). It cannot be run with `node`. It is loaded into the running ZAP container via the ZAP script API, not mounted as an entrypoint.

## `ZAP_CONTEXT_NAME` in `.env` defaults to `ICA-App-Context` (with dashes)
But the ZAP API always uses `contextId=1` (hardcoded) — the name is for display only. The context ID is always 1 because there is only ever one context per scan run.

## `collect-zap-evidence.sh` has two code paths
If `scripts/collect-zap-evidence.sh` exists on disk, `run-ica-authenticated-scan.sh` delegates to it. If it doesn't exist, a minimal inline fallback runs instead. Both write `evidence-summary.json` to `ZAP_REPORT_DIR`.
