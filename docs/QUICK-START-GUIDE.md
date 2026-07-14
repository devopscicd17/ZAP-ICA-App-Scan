# Quick Start Guide: ZAP Authenticated Scan for ICA Apps

This is a condensed guide to get you started quickly with ZAP authenticated scanning for ICA applications.

## 5-Minute Setup

### Step 1: Add Credentials to Toolchain (2 minutes)

In your IBM Cloud Toolchain:

1. Go to **Toolchain Settings** → **Secure Properties**
2. Add these properties:
   ```
   ibm_sso_username: your-email@ibm.com
   ibm_sso_password: your-secure-password
   app_url: https://your-ica-app.ibm.com
   ```

### Step 2: Update Pipeline Configuration (2 minutes)

Add this to your `.pipeline-config.yaml`:

```yaml
ica-security-scan:
  dind: true
  abort_on_failure: false
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    
    export ICA_APP_URL="$(get_env app_url)"
    export IBM_SSO_USERNAME="$(get_env ibm_sso_username)"
    export IBM_SSO_PASSWORD="$(get_env ibm_sso_password)"
    
    cd "$WORKSPACE/$(load_repo app-repo path)"
    source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
```

### Step 3: Run Pipeline (1 minute)

1. Commit and push your changes
2. Trigger the pipeline
3. Monitor the `ica-security-scan` stage

## Expected Output

```
[INFO] Starting ZAP authenticated scan...
[INFO] Target URL: https://your-ica-app.ibm.com
[SUCCESS] Authentication completed successfully
[INFO] Spider progress: 100%
[INFO] Active scan progress: 100%
[SUCCESS] Reports generated in: ./zap-reports
[INFO] Scan Results Summary:
  High Risk Alerts: 0
  Medium Risk Alerts: 2
  Low Risk Alerts: 5
  Informational Alerts: 10
[SUCCESS] ZAP Authenticated Scan Completed Successfully
```

## Reports Location

After scan completion, find reports in:
```
zap-reports/
├── zap-report-20260626_120000.html  # View in browser
├── zap-report-20260626_120000.xml   # For SonarQube
├── zap-report-20260626_120000.json  # For automation
└── zap-report-20260626_120000.md    # For documentation
```

## Common Configurations

### Increase Scan Timeout
```bash
export ZAP_SCAN_TIMEOUT="120"  # 2 hours
```

### Change Alert Threshold
```bash
export ZAP_ALERT_THRESHOLD="HIGH"  # Only fail on HIGH alerts
```

### Exclude URLs
```bash
export ZAP_EXCLUDE_URLS=".*logout.*,.*admin.*,.*delete.*"
```

### Reduce Scan Depth
```bash
export ZAP_MAX_DEPTH="3"  # Faster scans
```

## Troubleshooting Quick Fixes

### Authentication Fails
```bash
# Check credentials are set
echo "Username: ${IBM_SSO_USERNAME}"
echo "URL: ${ICA_APP_URL}"

# Enable debug mode
export PIPELINE_DEBUG=1
export ZAP_LOG_LEVEL="DEBUG"
```

### Scan Takes Too Long
```bash
export ZAP_SCAN_TIMEOUT="30"
export ZAP_MAX_DEPTH="3"
export ZAP_THREAD_COUNT="3"
```

### Docker Issues
```bash
# Ensure dind is enabled in .pipeline-config.yaml
# your-stage:
#   dind: true

# Check Docker in pipeline
docker --version

# View ZAP container logs
docker logs zap-scan-container
```

## Next Steps

1. ✅ Review the generated HTML report
2. ✅ Address any HIGH or MEDIUM findings
3. ✅ Customize scan configuration as needed
4. ✅ Integrate with your security workflow

## Need More Help?

- 📖 Full documentation: [README-ICA-AUTHENTICATED-SCAN.md](./README-ICA-AUTHENTICATED-SCAN.md)
- 🐛 Troubleshooting: See "Troubleshooting" section in full README
- 💬 Support: Contact your DevSecOps team

---

**Pro Tip:** Start with a short timeout (30 min) and low depth (3) for initial testing, then increase for comprehensive scans.