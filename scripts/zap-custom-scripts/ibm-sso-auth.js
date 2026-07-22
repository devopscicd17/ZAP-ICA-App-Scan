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
    // Decode HTML entities — IBM Toolchain web UI stores property values HTML-encoded
    var appUrl      = _htmlDecode(_param(paramsValues, "ICA_APP_URL"));
    var ssoLoginUrl = _param(paramsValues, "IBM_SSO_LOGIN_URL")
                      || java.lang.System.getenv("IBM_SSO_LOGIN_URL")
                      || "https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20";

    if (!username || !password) {
        _log("ERROR: credentials.username or credentials.password is empty");
        // Return a minimal GET to the app rather than null so ZAP does not abort
        return _get(helper, appUrl);
    }
    if (!appUrl) {
        _log("ERROR: ICA_APP_URL is not set in script parameters or environment");
        // Cannot proceed without a target URL — perform a no-op GET to a known-good URL
        // Never return a bare prepareMessage() — the HTTP version field is null which causes NPE
        return _get(helper, "https://www.ibm.com/");
    }

    _log("User    : " + username);
    _log("App URL : " + appUrl);   // should show literal & not &amp;
    _log("SSO URL : " + ssoLoginUrl);

    try {
        // ------------------------------------------------------------------
        // Step 1 — Access protected resource to trigger SP-initiated SSO
        // Follow redirects so ZAP handles the 302→SSO chain automatically
        // and we land on the IdP login page containing the SAMLRequest form.
        // ------------------------------------------------------------------
        _log("Step 1: Accessing protected resource to get SAMLRequest...");
        var initMsg  = _getFollowRedirects(helper, appUrl);
        var initBody = _body(initMsg);
        _log("Initial HTTP status: " + _status(initMsg));

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

        var loginMsg    = _post(helper, idpAction, loginBody);
        var loginStatus = _status(loginMsg);
        _log("IdP response status: " + loginStatus);

        var loginRespBody = _body(loginMsg);

        // Handle HTTP 302 redirect from IdP — follow to get SAMLResponse page
        if (loginStatus === 302) {
            var location = loginMsg.getResponseHeader().getHeader("Location");
            if (location) {
                _log("Following IdP redirect to: " + location);
                loginMsg      = _getFollowRedirects(helper, location);
                loginRespBody = _body(loginMsg);
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
        _log("ACS response status: " + _status(acsMsg));

        // ------------------------------------------------------------------
        // Step 4 — Verify session by fetching the protected resource again
        // ------------------------------------------------------------------
        _log("Step 4: Verifying session...");
        var verifyMsg  = _getFollowRedirects(helper, appUrl);
        var verifyBody = _body(verifyMsg);
        var verifyStat = _status(verifyMsg);

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
        // Return a fallback GET to the app URL — never return a bare prepareMessage() since
        // the HTTP version field is null on a freshly prepared message which causes NPE in ZAP
        try {
            return _get(helper, appUrl);
        } catch (fallbackErr) {
            _log("EXCEPTION in fallback GET: " + fallbackErr);
            // Last resort: set the HTTP version so ZAP does not NPE on the version field
            var lastResort = helper.prepareMessage();
            lastResort.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
            lastResort.getRequestHeader().setMethod(HttpRequestHeader.GET);
            return lastResort;
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

/**
 * Perform a GET request WITHOUT following redirects.
 *
 * ZAP's HttpRequestHeader has a null `version` field on a freshly prepared
 * message.  Several internal methods (setMethod, setURI, and ZAP's response
 * parser inside sendAndReceive) call version.toUpperCase() and will NPE if
 * version is not set first.  Always call setVersion(HTTP11) before anything
 * else, and wrap sendAndReceive in its own try/catch so a malformed server
 * response does not propagate an NPE up through authenticate().
 */
function _get(helper, url) {
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
    msg.getRequestHeader().setMethod(HttpRequestHeader.GET);
    msg.getRequestHeader().setURI(new URI(url, true));
    msg.setRequestBody("");
    msg.getRequestHeader().setContentLength(0);
    try {
        helper.sendAndReceive(msg, false);
    } catch (sendErr) {
        _log("WARNING: sendAndReceive(GET) failed: " + sendErr);
        if (msg.getResponseHeader() !== null) {
            try { msg.getResponseHeader().setVersion(HttpRequestHeader.HTTP11); } catch (e2) {}
        }
    }
    return msg;
}

/**
 * Perform a GET request WITH redirect-following enabled.
 * Use for Step 1 where the app immediately 302s to the IBM SSO IdP.
 * ZAP's internal redirect handler avoids the version-null NPE because it
 * re-uses the existing message infrastructure rather than parsing from scratch.
 */
function _getFollowRedirects(helper, url) {
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
    msg.getRequestHeader().setMethod(HttpRequestHeader.GET);
    msg.getRequestHeader().setURI(new URI(url, true));
    msg.setRequestBody("");
    msg.getRequestHeader().setContentLength(0);
    try {
        helper.sendAndReceive(msg, true);   // true = follow redirects
    } catch (sendErr) {
        _log("WARNING: sendAndReceive(GET+redirects) failed: " + sendErr);
        // Fall back to no-redirect GET — may land on redirect page instead of IdP
        try {
            helper.sendAndReceive(msg, false);
        } catch (e2) {
            _log("WARNING: fallback GET also failed: " + e2);
        }
        if (msg.getResponseHeader() !== null) {
            try { msg.getResponseHeader().setVersion(HttpRequestHeader.HTTP11); } catch (e3) {}
        }
    }
    return msg;
}

function _post(helper, url, bodyStr) {
    var msg = helper.prepareMessage();
    msg.getRequestHeader().setVersion(HttpRequestHeader.HTTP11);
    msg.getRequestHeader().setMethod(HttpRequestHeader.POST);
    msg.getRequestHeader().setURI(new URI(url, true));
    msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
    msg.setRequestBody(bodyStr);
    msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
    try {
        helper.sendAndReceive(msg, false);
    } catch (sendErr) {
        _log("WARNING: sendAndReceive failed for POST " + url + " : " + sendErr);
        if (msg.getResponseHeader() !== null) {
            try { msg.getResponseHeader().setVersion(HttpRequestHeader.HTTP11); } catch (e2) {}
        }
    }
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

/** Safely get response body as string; returns "" on null/error. */
function _body(msg) {
    try {
        var b = msg.getResponseBody();
        return b !== null ? b.toString() : "";
    } catch (e) { return ""; }
}

/** Safely get response HTTP status code; returns 0 on null/error. */
function _status(msg) {
    try {
        var h = msg.getResponseHeader();
        return h !== null ? h.getStatusCode() : 0;
    } catch (e) { return 0; }
}

/**
 * Decode HTML entities in a string.
 * IBM Toolchain stores property values HTML-encoded when set via the web UI,
 * so &amp; appears literally in the URL instead of &.
 */
function _htmlDecode(str) {
    if (!str) return str;
    return String(str)
        .replace(/&amp;/g,  '&')
        .replace(/&lt;/g,   '<')
        .replace(/&gt;/g,   '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g,  "'");
}

// Made with Bob
