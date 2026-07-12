/**
 * ZAP Authentication Script for IBM SSO (IBM Consulting Advantage)
 * This script handles IBM SSO authentication for ICA applications
 * 
 * Script Type: Authentication
 * Script Engine: Oracle Nashorn
 * 
 * Required Parameters:
 * - IBM_SSO_USERNAME: IBM SSO username/email
 * - IBM_SSO_PASSWORD: IBM SSO password
 * - ICA_APP_URL: Target ICA application URL
 * - IBM_SSO_LOGIN_URL: IBM SSO login endpoint (default: https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20)
 */

// Import required Java classes for HTTP operations
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpMessage = Java.type('org.parosproxy.paros.network.HttpMessage');
var URI = Java.type('org.apache.commons.httpclient.URI');
var HttpMethodType = Java.type('org.zaproxy.zap.network.HttpRequestBody');

/**
 * Main authentication function called by ZAP
 * @param helper - ZAP authentication helper object
 * @param paramsValues - Map of parameter values
 * @param credentials - User credentials object
 * @returns Authentication result object
 */
function authenticate(helper, paramsValues, credentials) {
    print("Starting IBM SSO authentication for ICA application...");
    
    // Get configuration from environment or parameters
    var username = credentials.getParam("username") || java.lang.System.getenv("IBM_SSO_USERNAME");
    var password = credentials.getParam("password") || java.lang.System.getenv("IBM_SSO_PASSWORD");
    var appUrl = paramsValues.get("ICA_APP_URL") || java.lang.System.getenv("ICA_APP_URL");
    var ssoLoginUrl = paramsValues.get("IBM_SSO_LOGIN_URL") || java.lang.System.getenv("IBM_SSO_LOGIN_URL") || "https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20";
    
    if (!username || !password || !appUrl) {
        print("ERROR: Missing required authentication parameters");
        print("Required: IBM_SSO_USERNAME, IBM_SSO_PASSWORD, ICA_APP_URL");
        return newAuthenticationResult(false, "Missing required authentication parameters");
    }
    
    print("Authenticating user: " + username);
    print("Target application: " + appUrl);
    
    try {
        // Step 1: Initiate SSO flow by accessing the protected application
        print("Step 1: Initiating SSO flow...");
        var initiateMsg = helper.prepareMessage();
        initiateMsg.getRequestHeader().setURI(new URI(appUrl, true));
        initiateMsg.getRequestHeader().setMethod("GET");
        helper.sendAndReceive(initiateMsg);
        
        var initiateResponse = initiateMsg.getResponseBody().toString();
        print("Initial response status: " + initiateMsg.getResponseHeader().getStatusCode());
        
        // Step 2: Extract SAML request and relay state from redirect
        var samlRequest = extractParameter(initiateResponse, "SAMLRequest");
        var relayState = extractParameter(initiateResponse, "RelayState");
        
        if (!samlRequest) {
            print("WARNING: No SAML request found, attempting direct login...");
        }
        
        // Step 3: Submit credentials to IBM SSO
        print("Step 2: Submitting credentials to IBM SSO...");
        var loginMsg = helper.prepareMessage();
        loginMsg.getRequestHeader().setURI(new URI(ssoLoginUrl, true));
        loginMsg.getRequestHeader().setMethod("POST");
        loginMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
        
        // Build login form data
        var loginData = "username=" + encodeURIComponent(username) + 
                       "&password=" + encodeURIComponent(password);
        
        if (samlRequest) {
            loginData += "&SAMLRequest=" + encodeURIComponent(samlRequest);
        }
        if (relayState) {
            loginData += "&RelayState=" + encodeURIComponent(relayState);
        }
        
        loginMsg.setRequestBody(loginData);
        loginMsg.getRequestHeader().setContentLength(loginMsg.getRequestBody().length());
        
        helper.sendAndReceive(loginMsg);
        
        var loginStatus = loginMsg.getResponseHeader().getStatusCode();
        print("Login response status: " + loginStatus);
        
        // Step 4: Handle SAML response and complete authentication
        if (loginStatus == 200 || loginStatus == 302) {
            var loginResponse = loginMsg.getResponseBody().toString();
            var samlResponse = extractParameter(loginResponse, "SAMLResponse");
            
            if (samlResponse) {
                print("Step 3: Processing SAML response...");
                
                // Extract ACS URL (Assertion Consumer Service)
                var acsUrl = extractFormAction(loginResponse) || appUrl + "/saml/acs";
                
                var samlMsg = helper.prepareMessage();
                samlMsg.getRequestHeader().setURI(new URI(acsUrl, true));
                samlMsg.getRequestHeader().setMethod("POST");
                samlMsg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
                
                var samlData = "SAMLResponse=" + encodeURIComponent(samlResponse);
                if (relayState) {
                    samlData += "&RelayState=" + encodeURIComponent(relayState);
                }
                
                samlMsg.setRequestBody(samlData);
                samlMsg.getRequestHeader().setContentLength(samlMsg.getRequestBody().length());
                
                helper.sendAndReceive(samlMsg);
                
                var samlStatus = samlMsg.getResponseHeader().getStatusCode();
                print("SAML response status: " + samlStatus);
                
                // Step 5: Verify authentication by checking session
                print("Step 4: Verifying authentication...");
                var verifyMsg = helper.prepareMessage();
                verifyMsg.getRequestHeader().setURI(new URI(appUrl, true));
                verifyMsg.getRequestHeader().setMethod("GET");
                helper.sendAndReceive(verifyMsg);
                
                var verifyResponse = verifyMsg.getResponseBody().toString();
                var verifyStatus = verifyMsg.getResponseHeader().getStatusCode();
                
                // Check for successful authentication indicators
                var isAuthenticated = verifyStatus == 200 && 
                                    !verifyResponse.contains("login") && 
                                    !verifyResponse.contains("Sign in") &&
                                    !verifyResponse.contains("w3id.sso.ibm.com");
                
                if (isAuthenticated) {
                    print("SUCCESS: Authentication completed successfully");
                    print("Session cookies established");
                    return newAuthenticationResult(true, "Authentication successful");
                } else {
                    print("ERROR: Authentication verification failed");
                    return newAuthenticationResult(false, "Authentication verification failed");
                }
            } else {
                print("ERROR: No SAML response received from IBM SSO");
                return newAuthenticationResult(false, "No SAML response received");
            }
        } else {
            print("ERROR: Login failed with status: " + loginStatus);
            return newAuthenticationResult(false, "Login failed with status: " + loginStatus);
        }
        
    } catch (e) {
        print("ERROR: Authentication exception: " + e.message);
        e.printStackTrace();
        return newAuthenticationResult(false, "Authentication exception: " + e.message);
    }
}

/**
 * Extract parameter value from HTML/response
 */
function extractParameter(html, paramName) {
    var pattern = new RegExp('name="' + paramName + '"\\s+value="([^"]+)"', 'i');
    var match = pattern.exec(html);
    if (match && match.length > 1) {
        return match[1];
    }
    
    // Try alternative pattern
    pattern = new RegExp(paramName + '=([^&\\s"]+)', 'i');
    match = pattern.exec(html);
    if (match && match.length > 1) {
        return match[1];
    }
    
    return null;
}

/**
 * Extract form action URL from HTML
 */
function extractFormAction(html) {
    var pattern = /<form[^>]+action="([^"]+)"/i;
    var match = pattern.exec(html);
    if (match && match.length > 1) {
        return match[1];
    }
    return null;
}

/**
 * URL encode a string
 */
function encodeURIComponent(str) {
    return java.net.URLEncoder.encode(str, "UTF-8");
}

/**
 * Create authentication result object
 */
function newAuthenticationResult(success, message) {
    var AuthenticationResult = Java.type('org.zaproxy.zap.authentication.AuthenticationResult');
    if (success) {
        return AuthenticationResult.newSuccessfulResult(message);
    } else {
        return AuthenticationResult.newFailedResult(message);
    }
}

/**
 * Get required parameter names for ZAP UI
 */
function getRequiredParamsNames() {
    return ["ICA_APP_URL"];
}

/**
 * Get optional parameter names for ZAP UI
 */
function getOptionalParamsNames() {
    return ["IBM_SSO_LOGIN_URL"];
}

/**
 * Get credentials parameter names for ZAP UI
 */
function getCredentialsParamsNames() {
    return ["username", "password"];
}

/**
 * Logging helper
 */
function print(message) {
    java.lang.System.out.println("[IBM-SSO-Auth] " + message);
}

// Made with Bob
