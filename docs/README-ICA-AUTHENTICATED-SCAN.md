# ZAP DAST Authenticated Scan for ICA Applications

This guide provides comprehensive instructions for performing OWASP ZAP Dynamic Application Security Testing (DAST) with authenticated scanning for IBM Consulting Advantage (ICA) applications using IBM SSO authentication in IBM Cloud Toolchain pipelines.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Pipeline Integration](#pipeline-integration)
- [Authentication Flow](#authentication-flow)
- [Customization](#customization)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [FAQ](#faq)

## Overview

This solution provides script-based authentication for ZAP DAST scanning of ICA applications that use IBM SSO (w3id) for authentication. Unlike browser-based authentication, this approach is fully compatible with CI/CD pipelines and doesn't require a graphical interface.

### Key Features

- ✅ **Script-based authentication** - No browser required, fully automated
- ✅ **IBM SSO integration** - Native support for IBM w3id SSO
- ✅ **Full scan coverage** - Spider + Active scan with authentication
- ✅ **Pipeline-ready** - Designed for IBM Cloud Toolchain
- ✅ **Comprehensive reporting** - HTML, XML, JSON, and Markdown reports
- ✅ **Evidence collection** - Automatic evidence gathering for compliance
- ✅ **Configurable thresholds** - Fail builds based on security findings

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    IBM Cloud Toolchain                       │
│                                                              │
│  ┌────────────────────────────────────────────────────┐    │
│  │         Dynamic Scan Stage                          │    │
│  │                                                      │    │
│  │  1. Load Environment Configuration                  │    │
│  │     (.env.ica-authenticated-scan.sh)               │    │
│  │                                                      │    │
│  │  2. Start ZAP Daemon/Docker                        │    │
│  │                                                      │    │
│  │  3. Load Authentication Script                      │    │
│  │     (ibm-sso-auth.js)                              │    │
│  │                                                      │    │
│  │  4. Configure ZAP Context                          │    │
│  │     - Set target URL                                │    │
│  │     - Configure authentication                      │    │
│  │     - Set logged in/out indicators                 │    │
│  │                                                      │    │
│  │  5. Create Authenticated User                       │    │
│  │     - Username: IBM SSO email                       │    │
│  │     - Password: IBM SSO password                    │    │
│  │                                                      │    │
│  │  6. Perform Spider Scan (as user)                  │    │
│  │                                                      │    │
│  │  7. Perform Active Scan (as user)                  │    │
│  │                                                      │    │
│  │  8. Generate Reports                                │    │
│  │                                                      │    │
│  │  9. Collect Evidence                                │    │
│  │                                                      │    │
│  │  10. Analyze Results & Exit                         │    │
│  └────────────────────────────────────────────────────┘    │
│                                                              │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                  ┌──────────────────┐
                  │  ICA Application │
                  │  (IBM SSO Auth)  │
                  └──────────────────┘
```

## Prerequisites

### Required Tools

- **Docker** - Required for running ZAP in IBM Cloud Toolchain (automatically available with `dind: true`)
- **jq** - JSON processor for report analysis (pre-installed in pipeline base image)
- **curl** - For ZAP API interactions (pre-installed in pipeline base image)
- **bash** 4.0 or later (pre-installed in pipeline base image)

**Note:** The script automatically uses the official OWASP ZAP Docker image (`owasp/zap2docker-stable`). No local ZAP installation is required.

### Required Credentials

You need the following credentials configured in your IBM Cloud Toolchain:

1. **IBM SSO Username** - Your IBM w3id email address
2. **IBM SSO Password** - Your IBM w3id password
3. **ICA Application URL** - The target application URL

### Pipeline Requirements

- IBM Cloud Toolchain with Continuous Delivery pipeline
- **Pipeline stage MUST have `dind: true`** for Docker-in-Docker support
- Pipeline base image: `icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61` or later
- Access to IBM Consulting Advantage environment

## Quick Start

### 1. Add Scripts to Your Repository

Copy the following files to your repository:

```bash
scripts/ci-cd/zap/
├── zap-custom-scripts/
│   ├── ibm-sso-auth.js                    # Authentication script
│   └── .env.ica-authenticated-scan.sh     # Environment configuration
├── zap-full-scan-authenticated.sh          # Main scan script
└── run-ica-authenticated-scan.sh           # Pipeline integration script
```

### 2. Configure Pipeline Secrets

In your IBM Cloud Toolchain, add the following secure properties:

```bash
# In Toolchain Settings > Secure Properties
ibm-sso-username: your-email@ibm.com
ibm-sso-password: your-secure-password
app-url: https://your-ica-app.ibm.com
```

### 3. Update .pipeline-config.yaml

Add or modify the `dynamic-scan` stage in your `.pipeline-config.yaml`:

```yaml
dynamic-scan:
  dind: true
  abort_on_failure: false
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    
    if [[ "$PIPELINE_DEBUG" == 1 ]]; then
      env
      set -x
    fi
    
    # Set required environment variables
    export ICA_APP_URL="$(get_env app-url)"
    export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
    export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
    
    # Optional: Configure scan parameters
    export ZAP_SCAN_TIMEOUT="60"
    export ZAP_ALERT_THRESHOLD="MEDIUM"
    export ZAP_MAX_DEPTH="5"
    
    # Run the authenticated scan
    cd "$WORKSPACE/$(load_repo app-repo path)"
    source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
```

### 4. Run the Pipeline

Trigger your pipeline and monitor the dynamic-scan stage. The scan will:

1. Authenticate using IBM SSO
2. Spider the application (crawl all pages)
3. Perform active security scanning
4. Generate reports
5. Collect evidence for compliance

## Configuration

### Environment Variables

#### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ICA_APP_URL` | Target ICA application URL | `https://your-app.ibm.com` |
| `IBM_SSO_USERNAME` | IBM SSO username/email | `user@ibm.com` |
| `IBM_SSO_PASSWORD` | IBM SSO password | `your-password` |

#### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `IBM_SSO_LOGIN_URL` | `https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20` | IBM SSO login endpoint |
| `ZAP_SCAN_TIMEOUT` | `60` | Scan timeout in minutes |
| `ZAP_ALERT_THRESHOLD` | `MEDIUM` | Alert threshold (HIGH/MEDIUM/LOW/INFORMATIONAL) |
| `ZAP_MAX_DEPTH` | `5` | Maximum spider crawl depth |
| `ZAP_THREAD_COUNT` | `5` | Number of scanning threads |
| `ZAP_REPORT_DIR` | `./zap-reports` | Directory for scan reports |
| `ZAP_CONTEXT_NAME` | `ICA-App-Context` | ZAP context name |
| `ZAP_EXCLUDE_URLS` | `.*logout.*,.*signout.*` | Comma-separated URL patterns to exclude |
| `ZAP_DOCKER_IMAGE` | `owasp/zap2docker-stable` | ZAP Docker image to use |
| `ZAP_CONTAINER_NAME` | `zap-scan-container` | Name for the ZAP Docker container |

### Customizing Authentication Indicators

Edit `.env.ica-authenticated-scan.sh` to customize logged in/out indicators:

```bash
# Logged in indicator - content that appears when authenticated
set_env ZAP_LOGGED_IN_INDICATOR "\\QLogout\\E|\\QMy Profile\\E|\\QDashboard\\E"

# Logged out indicator - content that appears when not authenticated
set_env ZAP_LOGGED_OUT_INDICATOR "\\QLogin\\E|\\QSign In\\E|\\Qw3id.sso.ibm.com\\E"
```

### Excluding URLs from Scan

To exclude specific URLs or patterns:

```bash
export ZAP_EXCLUDE_URLS=".*logout.*,.*signout.*,.*download.*,.*export.*"
```

## Pipeline Integration

### Option 1: Standalone Dynamic Scan Stage

```yaml
dynamic-scan:
  dind: true
  abort_on_failure: false
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    export ICA_APP_URL="$(get_env app-url)"
    export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
    export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
    
    cd "$WORKSPACE/$(load_repo app-repo path)"
    source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
```

### Option 2: Integrated with Existing Dynamic Scan

Modify your existing `dynamic-scan` stage:

```yaml
dynamic-scan:
  dind: true
  abort_on_failure: false
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    
    if [ -z "$(get_env opt-in-dynamic-scan "")" ]; then
      echo "Dynamic scan not enabled"
      exit 0
    fi
    
    # Check if ICA authenticated scan is requested
    if [ "$(get_env use-ica-authenticated-scan "")" == "true" ]; then
      export ICA_APP_URL="$(get_env app-url)"
      export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
      export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
      
      cd "$WORKSPACE/$(load_repo app-repo path)"
      source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
    else
      # Run standard ZAP scan
      ${COMMONS_PATH}/dynamic-scan/trigger-async-zap.sh \
        --api "definitions/definitions.json,public/swagger.yaml" \
        --ui "scripts/ci-cd/zap/uiscripts/run.sh" \
        --environment-setup "scripts/ci-cd/zap/zap-custom-scripts/.env.dynamic-scan.sh"
    fi
```

### Option 3: Separate Pipeline Job

Create a dedicated pipeline job for authenticated scanning:

```yaml
ica-security-scan:
  dind: true
  abort_on_failure: true
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    
    # Only run in specific environments
    if [[ "$(get_env target-environment)" != "staging" ]] && \
       [[ "$(get_env target-environment)" != "production" ]]; then
      echo "Skipping ICA authenticated scan for $(get_env target-environment)"
      exit 0
    fi
    
    export ICA_APP_URL="$(get_env app-url)"
    export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
    export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
    export ZAP_ALERT_THRESHOLD="HIGH"
    
    cd "$WORKSPACE/$(load_repo app-repo path)"
    source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
```

## Authentication Flow

### IBM SSO SAML Authentication Process

The authentication script follows this flow:

```
1. Access Protected Resource (ICA App)
   └─> Redirect to IBM SSO Login

2. Extract SAML Request
   └─> Parse SAMLRequest and RelayState parameters

3. Submit Credentials to IBM SSO
   └─> POST username and password with SAML data

4. Receive SAML Response
   └─> Extract SAMLResponse from IBM SSO

5. Submit SAML Response to ICA App
   └─> POST SAMLResponse to Assertion Consumer Service (ACS)

6. Establish Session
   └─> Receive session cookies from ICA application

7. Verify Authentication
   └─> Check for logged-in indicators in response
```

### Authentication Script (ibm-sso-auth.js)

The authentication script is written in JavaScript (Oracle Nashorn) and handles:

- SAML request/response parsing
- IBM SSO credential submission
- Session establishment
- Authentication verification

Key functions:

```javascript
authenticate(helper, paramsValues, credentials)
  ├─> Initiate SSO flow
  ├─> Extract SAML parameters
  ├─> Submit credentials
  ├─> Process SAML response
  └─> Verify authentication
```

## Customization

### Modifying Authentication Logic

Edit `scripts/ci-cd/zap/zap-custom-scripts/ibm-sso-auth.js`:

```javascript
// Add custom headers
loginMsg.getRequestHeader().setHeader("X-Custom-Header", "value");

// Modify login data
var loginData = "username=" + encodeURIComponent(username) + 
               "&password=" + encodeURIComponent(password) +
               "&custom_field=value";

// Add additional verification steps
var additionalCheck = verifyResponse.contains("expected-content");
```

### Custom Scan Policies

Create a custom scan policy file:

```bash
# Create custom policy
cat > custom-scan-policy.policy <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <policy>Custom ICA Scan Policy</policy>
  <scanner>
    <level>MEDIUM</level>
    <strength>MEDIUM</strength>
  </scanner>
  <!-- Add specific scanner configurations -->
</configuration>
EOF

# Use in scan
export ZAP_SCAN_POLICY="custom-scan-policy.policy"
```

### Adding Custom Scan Rules

To enable/disable specific scan rules:

```bash
# Disable noisy rules
export ZAP_DISABLE_RULES="10202,10201,10096"

# Enable only specific rules
export ZAP_ENABLE_RULES="40012,40014,40016,40017,40018"
```

## Troubleshooting

### Common Issues

#### 1. Authentication Fails

**Symptoms:**
- "Authentication verification failed" error
- Scan shows login pages instead of authenticated content

**Solutions:**
```bash
# Check credentials
echo "Username: ${IBM_SSO_USERNAME}"
echo "Password length: ${#IBM_SSO_PASSWORD}"

# Verify logged in/out indicators
export ZAP_LOGGED_IN_INDICATOR="\\QLogout\\E"
export ZAP_LOGGED_OUT_INDICATOR="\\QLogin\\E"

# Enable debug logging
export ZAP_LOG_LEVEL="DEBUG"
export ZAP_VERBOSE="true"
```

#### 2. Scan Timeout

**Symptoms:**
- Scan stops before completion
- "Scan timeout reached" message

**Solutions:**
```bash
# Increase timeout
export ZAP_SCAN_TIMEOUT="120"  # 2 hours

# Reduce scan depth
export ZAP_MAX_DEPTH="3"

# Reduce thread count
export ZAP_THREAD_COUNT="3"
```

#### 3. Docker Issues

**Symptoms:**
- "Docker is not installed or not in PATH" error
- "ZAP container stopped unexpectedly" error
- Container fails to start

**Solutions:**
```bash
# Verify dind is enabled in pipeline stage
# In .pipeline-config.yaml:
# your-stage:
#   dind: true

# Check Docker availability in pipeline
docker --version
docker ps

# View container logs
docker logs zap-scan-container

# Use different ZAP image
export ZAP_DOCKER_IMAGE="owasp/zap2docker-weekly"

# Check container status
docker ps -a --filter "name=zap-scan-container"
```

#### 4. Missing Reports

**Symptoms:**
- No reports generated
- Empty report directory

**Solutions:**
```bash
# Check report directory permissions
ls -la ${ZAP_REPORT_DIR}

# Verify ZAP completed successfully
tail -f ${ZAP_REPORT_DIR}/zap-daemon.log

# Check for errors in scan
grep -i error ${ZAP_REPORT_DIR}/*.log
```

### Debug Mode

Enable comprehensive debugging:

```bash
# Enable pipeline debug
export PIPELINE_DEBUG=1

# Enable ZAP debug
export ZAP_LOG_LEVEL="DEBUG"
export ZAP_VERBOSE="true"

# Enable bash debug
set -x

# Run scan
source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
```

### Viewing ZAP Logs

```bash
# View container logs (real-time)
docker logs -f zap-scan-container

# View container logs (last 50 lines)
docker logs --tail 50 zap-scan-container

# View authentication attempts
docker logs zap-scan-container 2>&1 | grep -i "auth"

# View scan progress
docker logs zap-scan-container 2>&1 | grep -i "progress"

# Check if container is running
docker ps --filter "name=zap-scan-container"
```

## Security Considerations

### Credential Management

**DO:**
- ✅ Store credentials in IBM Cloud Toolchain secure properties
- ✅ Use environment variables for credential passing
- ✅ Rotate credentials regularly
- ✅ Use service accounts with minimal permissions

**DON'T:**
- ❌ Hardcode credentials in scripts
- ❌ Commit credentials to version control
- ❌ Log credentials in plain text
- ❌ Share credentials across teams

### Secure Configuration

```bash
# Use secure properties in pipeline
export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"

# Mask sensitive data in logs
set +x  # Disable bash debug before handling credentials
export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
set -x  # Re-enable debug after
```

### Network Security

- Run scans from trusted networks
- Use VPN for accessing internal ICA applications
- Configure firewall rules appropriately
- Monitor scan traffic for anomalies

### Scan Scope

```bash
# Limit scan scope to prevent unintended testing
export ZAP_EXCLUDE_URLS=".*logout.*,.*admin.*,.*delete.*,.*remove.*"

# Set maximum scan duration
export ZAP_SCAN_TIMEOUT="60"

# Limit crawl depth
export ZAP_MAX_DEPTH="5"
```

## FAQ

### Q: Can I use this for non-ICA applications?

**A:** Yes, but you'll need to modify the authentication script (`ibm-sso-auth.js`) to match your application's authentication flow.

### Q: How do I scan multiple ICA applications?

**A:** Create separate pipeline jobs or loop through applications:

```bash
for app_url in "${ICA_APP_URLS[@]}"; do
  export ICA_APP_URL="${app_url}"
  source scripts/ci-cd/zap/run-ica-authenticated-scan.sh
done
```

### Q: Can I run this locally?

**A:** Yes, set the required environment variables and run:

```bash
export ICA_APP_URL="https://your-app.ibm.com"
export IBM_SSO_USERNAME="your-email@ibm.com"
export IBM_SSO_PASSWORD="your-password"

bash scripts/ci-cd/zap/zap-full-scan-authenticated.sh
```

### Q: How do I handle multi-factor authentication (MFA)?

**A:** For MFA-enabled accounts, you'll need to:
1. Use a service account without MFA, or
2. Implement MFA token generation in the authentication script, or
3. Use application-specific passwords if supported

### Q: What if my ICA app uses a different SSO provider?

**A:** Modify the `IBM_SSO_LOGIN_URL` and update the authentication script to match your SSO provider's flow.

### Q: How do I integrate with other security tools?

**A:** ZAP reports can be consumed by:
- SonarQube (XML format)
- DefectDojo (JSON format)
- ThreadFix (XML format)
- Custom parsers (JSON format)

### Q: Can I schedule scans?

**A:** Yes, configure your IBM Cloud Toolchain pipeline with:
- Timed triggers
- Git commit triggers
- Manual triggers
- API-triggered scans

## Support and Resources

### Documentation

- [OWASP ZAP Documentation](https://www.zaproxy.org/docs/)
- [IBM Cloud Toolchain Docs](https://cloud.ibm.com/docs/ContinuousDelivery)
- [IBM SSO Documentation](https://w3.ibm.com/w3publisher/w3id)

### Getting Help

1. Check the [Troubleshooting](#troubleshooting) section
2. Review ZAP logs in `${ZAP_REPORT_DIR}/zap-daemon.log`
3. Contact your DevSecOps team
4. Open an issue in your repository

### Contributing

To improve these scripts:

1. Fork the repository
2. Make your changes
3. Test thoroughly
4. Submit a pull request
5. Update documentation

## License

This solution is provided as-is for use within IBM projects. Refer to your project's license file for details.

---

**Last Updated:** 2026-06-26  
**Version:** 1.0.0  
**Maintainer:** DevSecOps Team