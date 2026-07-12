# IBM Cloud Toolchain Setup Guide for ZAP-ICA-App-Scan

This guide provides step-by-step instructions to set up OWASP ZAP authenticated scanning in your IBM Cloud Toolchain.

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Step 1: Create/Access Your Toolchain](#step-1-createaccess-your-toolchain)
3. [Step 2: Add Git Repository](#step-2-add-git-repository)
4. [Step 3: Configure Secure Properties](#step-3-configure-secure-properties)
5. [Step 4: Create Delivery Pipeline](#step-4-create-delivery-pipeline)
6. [Step 5: Configure Pipeline Stages](#step-5-configure-pipeline-stages)
7. [Step 6: Test the Setup](#step-6-test-the-setup)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before you begin, ensure you have:

- ✅ IBM Cloud account with access to Toolchain
- ✅ ICA application URL
- ✅ IBM SSO credentials (w3id username and password)
- ✅ Git repository with your application code
- ✅ Permissions to create/modify toolchains

---

## Step 1: Create/Access Your Toolchain

### Option A: Create New Toolchain

1. **Log in to IBM Cloud**
   - Go to https://cloud.ibm.com
   - Navigate to **DevOps** → **Toolchains**

2. **Create Toolchain**
   - Click **Create toolchain**
   - Select **Build your own toolchain**
   - Enter toolchain name: `your-app-security-scan`
   - Select region: `us-south` (or your preferred region)
   - Click **Create**

### Option B: Use Existing Toolchain

1. Navigate to your existing toolchain
2. You'll add the ZAP scan to this toolchain

---

## Step 2: Add Git Repository

### If Using GitHub/GitLab/Bitbucket

1. **Add Git Integration**
   - In your toolchain, click **Add tool**
   - Select **GitHub** (or your Git provider)
   - Authorize IBM Cloud to access your repository
   - Select your repository containing the ZAP scripts

2. **Repository Structure**
   ```
   your-repo/
   ├── .pipeline-config.yaml
   └── scripts/
       ├── zap-full-scan-authenticated.sh
       ├── run-ica-authenticated-scan.sh
       └── zap-custom-scripts/
           ├── ibm-sso-auth.js
           └── .env.ica-authenticated-scan.sh
   ```

### Upload Scripts to Your Repository

```bash
# Clone your repository
git clone https://github.com/your-org/your-repo.git
cd your-repo

# Copy ZAP scripts
mkdir -p scripts/zap-custom-scripts
cp /path/to/ZAP-ICA-App-Scan/scripts/*.sh scripts/
cp /path/to/ZAP-ICA-App-Scan/scripts/zap-custom-scripts/* scripts/zap-custom-scripts/

# Commit and push
git add scripts/
git commit -m "Add ZAP authenticated scan scripts"
git push origin main
```

---

## Step 3: Configure Secure Properties

Secure properties store sensitive credentials safely in your toolchain.

### Add Secure Properties

1. **Access Toolchain Settings**
   - In your toolchain, click the **⚙️ Settings** icon (top right)
   - Or go to: `https://cloud.ibm.com/devops/toolchains/<your-toolchain-id>?env_id=ibm:yp:us-south`

2. **Navigate to Secure Properties**
   - Click **Secure properties** in the left sidebar
   - Or use the **Environment properties** tab

3. **Add Required Properties**

   Click **Add property** for each of the following:

   | Property Name | Type | Value | Description |
   |--------------|------|-------|-------------|
   | `ibm-sso-username` | Secure | `your-email@ibm.com` | Your IBM SSO username |
   | `ibm-sso-password` | Secure | `your-password` | Your IBM SSO password |
   | `app-url` | Text | `https://your-ica-app.ibm.com` | Target ICA application URL |

4. **Optional Properties**

   | Property Name | Type | Value | Description |
   |--------------|------|-------|-------------|
   | `zap-scan-timeout` | Text | `60` | Scan timeout in minutes |
   | `zap-alert-threshold` | Text | `MEDIUM` | Alert threshold (HIGH/MEDIUM/LOW) |
   | `zap-max-depth` | Text | `5` | Maximum crawl depth |

5. **Save Properties**
   - Click **Save** after adding each property

---

## Step 4: Create Delivery Pipeline

### Add Delivery Pipeline Tool

1. **Add Pipeline**
   - In your toolchain, click **Add tool**
   - Select **Delivery Pipeline**
   - Enter pipeline name: `Security Scan Pipeline`
   - Select pipeline type: **Tekton** or **Classic**
   - Click **Create Integration**

2. **Configure Pipeline**
   - Click on the newly created pipeline to open it

---

## Step 5: Configure Pipeline Stages

### Option A: Using .pipeline-config.yaml (Recommended)

1. **Create `.pipeline-config.yaml` in your repository root**

```yaml
version: '1'

# Setup stage - prepare environment
setup:
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    echo "Setting up environment..."
    
# Build stage (if needed)
build:
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    echo "Build stage - add your build commands here"

# ZAP Dynamic Security Scan
dynamic-scan:
  dind: true  # REQUIRED: Enable Docker-in-Docker
  abort_on_failure: false  # Don't fail pipeline on security findings
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    
    # Enable debug mode (optional)
    if [[ "$PIPELINE_DEBUG" == 1 ]]; then
      env | sort
      set -x
    fi
    
    # Set required environment variables from secure properties
    export ICA_APP_URL="$(get_env app-url)"
    export IBM_SSO_USERNAME="$(get_env ibm-sso-username)"
    export IBM_SSO_PASSWORD="$(get_env ibm-sso-password)"
    
    # Optional: Set scan configuration
    export ZAP_SCAN_TIMEOUT="$(get_env zap-scan-timeout "60")"
    export ZAP_ALERT_THRESHOLD="$(get_env zap-alert-threshold "MEDIUM")"
    export ZAP_MAX_DEPTH="$(get_env zap-max-depth "5")"
    
    # Navigate to repository
    cd "$WORKSPACE/$(load_repo app-repo path)"
    
    # Run ZAP authenticated scan
    source scripts/run-ica-authenticated-scan.sh
    
    # Exit with scan result
    exit $?

# Deploy stage (if needed)
deploy:
  image: icr.io/continuous-delivery/pipeline/pipeline-base-ubi:3.61
  script: |
    #!/usr/bin/env bash
    echo "Deploy stage - add your deployment commands here"
```

2. **Commit and push the configuration**

```bash
git add .pipeline-config.yaml
git commit -m "Add ZAP security scan pipeline configuration"
git push origin main
```

### Option B: Manual Pipeline Configuration (Classic Pipeline)

If not using `.pipeline-config.yaml`, configure stages manually:

#### Stage 1: Build (Optional)

1. Click **Add Stage**
2. **Input tab:**
   - Input type: `Git Repository`
   - Select your repository
   - Branch: `main` (or your default branch)

3. **Jobs tab:**
   - Click **Add Job** → **Build**
   - Builder type: `Shell Script`
   - Script:
   ```bash
   #!/bin/bash
   echo "Build completed"
   ```

#### Stage 2: ZAP Security Scan

1. Click **Add Stage**
2. **Input tab:**
   - Input type: `Build Artifacts`
   - Stage: `Build` (from previous stage)

3. **Jobs tab:**
   - Click **Add Job** → **Deploy**
   - Deployer type: `Shell Script`
   - **IMPORTANT:** Enable Docker by adding to stage properties:
     ```
     dind: true
     ```

4. **Script:**
   ```bash
   #!/usr/bin/env bash
   set -euo pipefail
   
   # Enable debug (optional)
   if [[ "$PIPELINE_DEBUG" == 1 ]]; then
     env | sort
     set -x
   fi
   
   # Get credentials from secure properties
   export ICA_APP_URL="$APP_URL"
   export IBM_SSO_USERNAME="$IBM_SSO_USERNAME"
   export IBM_SSO_PASSWORD="$IBM_SSO_PASSWORD"
   
   # Optional configuration
   export ZAP_SCAN_TIMEOUT="${ZAP_SCAN_TIMEOUT:-60}"
   export ZAP_ALERT_THRESHOLD="${ZAP_ALERT_THRESHOLD:-MEDIUM}"
   export ZAP_MAX_DEPTH="${ZAP_MAX_DEPTH:-5}"
   
   # Run ZAP scan
   cd "$WORKSPACE"
   source scripts/run-ica-authenticated-scan.sh
   ```

5. **Environment Properties:**
   - Click **Environment properties** tab
   - Add text properties:
     - `APP_URL`: `${app-url}`
     - `IBM_SSO_USERNAME`: `${ibm-sso-username}`
     - `IBM_SSO_PASSWORD`: `${ibm-sso-password}`

---

## Step 6: Test the Setup

### Run the Pipeline

1. **Trigger Pipeline**
   - Go to your Delivery Pipeline
   - Click **Run Pipeline** or **▶️ Run**
   - Select the branch to run

2. **Monitor Execution**
   - Watch the pipeline stages execute
   - Click on each stage to see logs
   - The ZAP scan stage will take 10-60 minutes depending on your app

3. **Expected Output**

   ```
   [INFO] Starting ZAP authenticated scan...
   [INFO] Docker found: Docker version 20.10.x
   [INFO] Starting ZAP Docker container...
   [SUCCESS] ZAP container started: zap-scan-container
   [INFO] Waiting for ZAP to be ready (this may take 1-2 minutes)...
   [SUCCESS] ZAP daemon is ready and responding
   [INFO] ZAP version: 2.14.0
   [INFO] Loading IBM SSO authentication script...
   [SUCCESS] Authentication script loaded
   [INFO] Starting spider scan...
   [INFO] Spider progress: 100%
   [INFO] Starting active scan...
   [INFO] Active scan progress: 100%
   [SUCCESS] Reports generated in: ./zap-reports
   [INFO] Scan Results Summary:
     High Risk Alerts: 0
     Medium Risk Alerts: 2
     Low Risk Alerts: 5
     Informational Alerts: 10
   [SUCCESS] ZAP Authenticated Scan Completed Successfully
   ```

4. **View Reports**
   - Reports are saved in the `zap-reports` directory
   - Download artifacts from the pipeline run
   - Reports include: HTML, XML, JSON, and Markdown formats

---

## Advanced Configuration

### Schedule Automated Scans

1. **Add Timer Trigger**
   - In pipeline settings, go to **Triggers**
   - Click **Add Trigger** → **Git Repository**
   - Enable **Run when a commit is pushed**
   - Or add **Timed Trigger** for scheduled scans:
     - Cron expression: `0 2 * * *` (daily at 2 AM)

### Integrate with Slack/Teams

1. **Add Slack Integration**
   - In toolchain, click **Add tool**
   - Select **Slack**
   - Configure webhook URL
   - Select events to notify

2. **Add Notification to Pipeline**
   ```yaml
   dynamic-scan:
     script: |
       # ... existing script ...
       
       # Send Slack notification
       if command -v send_slack_notification &> /dev/null; then
         send_slack_notification "ZAP scan completed for ${ICA_APP_URL}"
       fi
   ```

### Save Scan Evidence

```yaml
dynamic-scan:
  script: |
    # ... existing script ...
    
    # Save evidence to IBM Cloud
    if command -v save_artifact &> /dev/null; then
      save_artifact "zap-scan-reports" \
        "type=com.ibm.dynamic_scan" \
        "path=./zap-reports/*.html"
    fi
```

---

## Troubleshooting

### Issue 1: "Docker is not installed"

**Cause:** `dind: true` not enabled in pipeline stage

**Solution:**
```yaml
dynamic-scan:
  dind: true  # Add this line
  script: |
    # ... your script ...
```

### Issue 2: "Missing required environment variables"

**Cause:** Secure properties not configured or not accessible

**Solution:**
1. Verify secure properties are set in toolchain settings
2. Check property names match exactly (case-sensitive)
3. Ensure you're using `get_env` function:
   ```bash
   export ICA_APP_URL="$(get_env app-url)"
   ```

### Issue 3: "Authentication failed"

**Cause:** Invalid credentials or wrong application URL

**Solution:**
1. Verify credentials work by logging in manually to ICA app
2. Check application URL is correct and accessible
3. Enable debug mode:
   ```bash
   export PIPELINE_DEBUG=1
   export ZAP_LOG_LEVEL="DEBUG"
   ```

### Issue 4: "Scan timeout"

**Cause:** Application is large or slow to scan

**Solution:**
```bash
# Increase timeout
export ZAP_SCAN_TIMEOUT="120"  # 2 hours

# Reduce scan depth
export ZAP_MAX_DEPTH="3"

# Reduce thread count
export ZAP_THREAD_COUNT="3"
```

### Issue 5: "Container fails to start"

**Cause:** Docker image pull failure or resource constraints

**Solution:**
1. Check Docker image is accessible:
   ```bash
   docker pull owasp/zap2docker-stable
   ```
2. Use different image:
   ```bash
   export ZAP_DOCKER_IMAGE="owasp/zap2docker-weekly"
   ```
3. Check pipeline worker resources

### View Detailed Logs

```bash
# In pipeline script, add:
set -x  # Enable bash debug

# View ZAP container logs
docker logs zap-scan-container

# View ZAP daemon logs
cat ./zap-reports/zap-daemon.log
```

---

## Best Practices

### 1. Security

- ✅ Always use secure properties for credentials
- ✅ Never commit credentials to Git
- ✅ Rotate credentials regularly
- ✅ Use service accounts with minimal permissions

### 2. Performance

- ✅ Start with short timeout (30 min) for testing
- ✅ Increase timeout for comprehensive scans
- ✅ Use URL exclusions to skip non-critical pages
- ✅ Schedule scans during off-peak hours

### 3. Maintenance

- ✅ Review scan reports regularly
- ✅ Update ZAP Docker image monthly
- ✅ Keep authentication scripts updated
- ✅ Document any custom configurations

### 4. Integration

- ✅ Integrate with issue tracking (Jira, GitHub Issues)
- ✅ Send notifications to security team
- ✅ Archive reports for compliance
- ✅ Track metrics over time

---

## Next Steps

1. ✅ **Test the setup** with a simple application first
2. ✅ **Review the first scan report** and adjust thresholds
3. ✅ **Customize exclusions** based on your application
4. ✅ **Schedule regular scans** (daily/weekly)
5. ✅ **Integrate with your security workflow**

---

## Support

- **Documentation:** [docs/README-ICA-AUTHENTICATED-SCAN.md](docs/README-ICA-AUTHENTICATED-SCAN.md)
- **Quick Start:** [docs/QUICK-START-GUIDE.md](docs/QUICK-START-GUIDE.md)
- **IBM Cloud Docs:** https://cloud.ibm.com/docs/ContinuousDelivery
- **ZAP Documentation:** https://www.zaproxy.org/docs/

---

**Last Updated:** 2026-07-12  
**Version:** 1.0.0