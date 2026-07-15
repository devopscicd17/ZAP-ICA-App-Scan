/**
 * ZAP Authentication Script for IBM SSO (IBM Consulting Advantage)
 *
 * Script Type  : Authentication
 * Script Engine: ECMAScript : Graal.js  (ZAP 2.14+ / ghcr.io/zaproxy/zaproxy:stable)
 *                Oracle Nashorn          (ZAP 2.13 and earlier — legacy)
 *
 * Required ZAP Parameters (set via "Script parameters" in ZAP context):
 *   ICA_APP_URL       — Target ICA application URL
 *   IBM_SSO_LOGIN_URL — IBM SSO IdP endpoint (optional, falls back to env/default)
 *
 * Required User Credentials (set via "Users" in ZAP context):
 *   username          — IBM w3id email address
 *   password          — IBM w3id password
 *
 * The script follows the IBM w3id SAML2 POST-binding flow:
 *   1. GET protected resource → IdP redirect with SAMLRequest
 *   2. POST credentials to IdP → SAMLResponse
 *   3. POST SAMLResponse to SP ACS → session cookie
 *   4. GET protected resource again → verify session is active
 *
 * Return value: The last HttpMessage object.  ZAP uses the cookies on this
 * message for all subsequent scan requests.  We NEVER return null because
 * ZAP treats a null return as a hard authentication failure and may abort
 * the entire scan rather than simply logging a warning.
 */

// ---------------------------------------------------------------------------
// Java type imports — compatible with both GraalVM JS (Graal.js) and Nashorn
// ---------------------------------------------------------------------------
var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpMessage       = Java.type('org.parosproxy.paros.network.HttpMessage');
// org.apache.commons.httpclient.URI is available in ZAP 2.x
// org.apache.commons.httpclient3.URI was renamed in some builds — try both
var URI;
try {
    URI = Java.type('org.apache.commons.httpclient.URI');
} catch (e) {
    URI = Java.type('org.apache.commons.httpclient3.URI');
}

// ---------------------------------------------------------------------------
// Public API required by ZAP's Script-based Authentication
// ---------------------------------------------------------------------------

/**
 * Called by ZAP to perform authentication.
 *
 * @param {object} helper        — ZAP HttpSender helper
 * @param {Map}    paramsValues  — Script parameters from ZAP context
 * @param {object} credentials   — Credentials object for the current user
 * @returns {HttpMessage}        — The last HTTP message (ZAP inspects cookies)
 */
function authenticate(helper, paramsValues, credentials) {
    _log("=== IBM SSO Authentication START ===");

    var username    = credentials.getParam("username");
    var password    = credentials.getParam("password");
    var appUrl      = _param(paramsValues, "ICA_APP_URL");
    var ssoLoginUrl = _param(paramsValues, "IBM_SSO_LOGIN_URL")
                      || java.lang.System.getenv("IBM_SSO_LOGIN_URL")
                      || "https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20";

    if (!username || !password) {
        _log("ERROR: credentials.username or credentials.password is empty");
        // Return a minimal GET to the app rather than null so ZAP does not abort
        return _get(helper, appUrl || "about:blank");
    }
    if (!appUrl) {
        _log("ERROR: ICA_APP_URL is not set in script parameters or environment");
        // Cannot proceed without a target URL — return a safe dummy message
        var dummyMsg = helper.prepareMessage();
        return dummyMsg;
    }

    _log("User    : " + username);
    _log("App URL : " + appUrl);
    _log("SSO URL : " + ssoLoginUrl);

    try {
        // ------------------------------------------------------------------
        // Step 1 — Access protected resource to trigger SP-initiated SSO
        // ------------------------------------------------------------------
        _log("Step 1: Accessing protected resource to get SAMLRequest...");
        var initMsg = _get(helper, appUrl);
        var initBody = initMsg.getResponseBody().toString();
        _log("Initial HTTP status: " + initMsg.getResponseHeader().getStatusCode());

        var samlRequest = _extractHiddenField(initBody, "SAMLRequest");
        var relayState  = _extractHiddenField(initBody, "RelayState");
        var idpAction   = _extractFormAction(initBody) || ssoLoginUrl;

        if (!samlRequest) {
            _log("WARNING: SAMLRequest not found in initial response — app may not require SSO");
        }

        // ------------------------------------------------------------------
        // Step 2 — POST credentials to IBM SSO IdP
        // ------------------------------------------------------------------
        _log("Step 2: Posting credentials to IBM SSO IdP...");
        var loginBody = "username=" + _encode(username)
                      + "&password=" + _encode(password);
        if (samlRequest) loginBody += "&SAMLRequest=" + _encode(samlRequest);
        if (relayState)  loginBody += "&RelayState="  + _encode(relayState);

        var loginMsg = _post(helper, idpAction, loginBody);
        var loginStatus = loginMsg.getResponseHeader().getStatusCode();
        _log("IdP response status: " + loginStatus);

        var loginRespBody = loginMsg.getResponseBody().toString();

        // Handle HTTP 302 redirect from IdP — follow to get SAMLResponse page
        if (loginStatus === 302) {
            var location = loginMsg.getResponseHeader().getHeader("Location");
            if (location) {
                _log("Following IdP redirect to: " + location);
                loginMsg      = _get(helper, location);
                loginRespBody = loginMsg.getResponseBody().toString();
            }
        }

        var samlResponse   = _extractHiddenField(loginRespBody, "SAMLResponse");
        var relayState2    = _extractHiddenField(loginRespBody, "RelayState");
        var acsUrl         = _extractFormAction(loginRespBody) || (appUrl + "/saml/acs");

        if (!samlResponse) {
            _log("ERROR: No SAMLResponse found in IdP response — check credentials or SSO URL");
            // Return the IdP response so ZAP can inspect cookies / response body
            return loginMsg;
        }

        // ------------------------------------------------------------------
        // Step 3 — POST SAMLResponse to Service Provider ACS
        // ------------------------------------------------------------------
        _log("Step 3: Posting SAMLResponse to SP ACS: " + acsUrl);
        var acsBody = "SAMLResponse=" + _encode(samlResponse);
        if (relayState2) acsBody += "&RelayState=" + _encode(relayState2);

        var acsMsg = _post(helper, acsUrl, acsBody);
        _log("ACS response status: " + acsMsg.getResponseHeader().getStatusCode());

        // ------------------------------------------------------------------
        // Step 4 — Verify session by fetching the protected resource again
        // ------------------------------------------------------------------
        _log("Step 4: Verifying session...");
        var verifyMsg  = _get(helper, appUrl);
        var verifyBody = verifyMsg.getResponseBody().toString();
        var verifyStat = verifyMsg.getResponseHeader().getStatusCode();

        _log("Verification HTTP status: " + verifyStat);

        var stillOnLoginPage = verifyBody.toLowerCase().indexOf("w3id.sso.ibm.com") >= 0
                            || verifyBody.toLowerCase().indexOf("sign in") >= 0
                            || verifyBody.toLowerCase().indexOf("samlrequest") >= 0;

        if (verifyStat === 200 && !stillOnLoginPage) {
            _log("=== Authentication SUCCESSFUL ===");
        } else {
            _log("WARNING: Post-authentication check suggests login may have failed");
        }

        // ZAP uses the returned message's cookies for subsequent requests
        return verifyMsg;

    } catch (e) {
        _log("EXCEPTION during authentication: " + e);
        if (e.javaException) {
            e.javaException.printStackTrace();
        }
        // Return a fallback message rather than null to avoid aborting the scan
        try {
            return _get(helper, appUrl);
        } catch (fallbackErr) {
            _log("EXCEPTION in fallback GET: " + fallbackErr);
            return helper.prepareMessage();
        }
    }
}

/**
 * Required parameter names shown in ZAP context GUI.
 */
function getRequiredParamsNames() {
    return ["ICA_APP_URL"];
}

/**
 * Optional parameter names shown in ZAP context GUI.
 */
function getOptionalParamsNames() {
    return ["IBM_SSO_LOGIN_URL"];
}

/**
 * Credential field names shown in ZAP Users GUI.
 */
function getCredentialsParamsNames() {
    return ["username", "password"];
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

function _get(helper, url) {
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setMethod(HttpRequestHeader.GET);
    msg.getRequestHeader().setURI(new URI(url, true));
    msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
    msg.setRequestBody("");
    msg.getRequestHeader().setContentLength(0);
    helper.sendAndReceive(msg, false);
    return msg;
}

function _post(helper, url, bodyStr) {
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
    msg.getRequestHeader().setURI(new URI(url, true));
    msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
    msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    msg.setRequestBody(bodyStr);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
    helper.sendAndReceive(msg, false);
    return msg;
}

/** Safely read a script parameter (paramsValues is a Java Map). */
function _param(paramsValues, key) {
    try { return paramsValues.get(key) || null; } catch (e) { return null; }
}

/**
 * Extract an HTML hidden-field value, e.g.:
 *   <input type="hidden" name="SAMLRequest" value="PHNhbWxwOi..." />
 * Both single- and double-quoted values are handled.
 */
function _extractHiddenField(html, name) {
    // Try name="..." value="..." ordering
    var re1 = new RegExp(
        'name=["\']' + name + '["\'][^>]*?value=["\']([^"\']+)["\']', 'i');
    var m = re1.exec(html);
    if (m) return m[1];

    // Try value="..." name="..." ordering
    var re2 = new RegExp(
        'value=["\']([^"\']+)["\'][^>]*?name=["\']' + name + '["\']', 'i');
    m = re2.exec(html);
    if (m) return m[1];

    return null;
}

/** Extract the action URL from the first <form> tag. */
function _extractFormAction(html) {
    var m = /<form[^>]+action=["']([^"']+)["']/i.exec(html);
    return m ? m[1] : null;
}

/** URL-encode a string using Java. */
function _encode(str) {
    return java.net.URLEncoder.encode(String(str), "UTF-8");
}

function _log(msg) {
    java.lang.System.out.println("[IBM-SSO-Auth] " + msg);
}

// Made with Bob
