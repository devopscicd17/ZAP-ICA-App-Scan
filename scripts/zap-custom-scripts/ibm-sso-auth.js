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
var HttpResponseHeader = Java.type('org.parosproxy.paros.network.HttpResponseHeader');
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

    // Read appUrl from the OS environment variable — ZAP re-encodes & to &amp; when it
    // stores YAML script parameters in paramsValues, so paramsValues.get("ICA_APP_URL")
    // returns a double-encoded URL even after _htmlDecode.  The shell script exports
    // ICA_APP_URL with the decoded value, which Java inherits untouched.
    var appUrl = java.lang.System.getenv("ICA_APP_URL")
              || _htmlDecode(_param(paramsValues, "ICA_APP_URL"));

    var ssoLoginUrl = java.lang.System.getenv("IBM_SSO_LOGIN_URL")
                      || _htmlDecode(_param(paramsValues, "IBM_SSO_LOGIN_URL"))
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
        // _get/_getFollowRedirects/_post all catch internally — this block is a last safety net
        return _get(helper, appUrl);
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
 * Build a fresh HttpMessage using HttpRequestHeader's 3-arg constructor:
 *   new HttpRequestHeader(method, uri, version)
 *
 * This bypasses all the setter NPE issues — ZAP's setMethod()/setURI() both
 * call this.version.toUpperCase() internally and NPE if version is null.
 * Using the constructor sets all three fields atomically before any getter
 * or internal method can read version.
 */
function _buildMsg(method, url) {
    // Decode any residual HTML entities before passing to URI parser.
    // ZAP's URI class cannot handle &amp; literally — it must be & in the query string.
    var cleanUrl = _htmlDecode(String(url));
    var uri    = new URI(cleanUrl, false);  // false = url is NOT pre-escaped; let URI parse it
    var header = new HttpRequestHeader(method, uri, HttpRequestHeader.HTTP11);
    return new HttpMessage(header);
}

/** GET without following redirects. */
function _get(helper, url) {
    try {
        var msg = _buildMsg(HttpRequestHeader.GET, url);
        msg.setRequestBody("");
        msg.getRequestHeader().setContentLength(0);
        helper.sendAndReceive(msg, false);
        return msg;
    } catch (e) {
        _log("WARNING: _get failed for " + url + " : " + e);
        return _emptyMsg();
    }
}

/** GET following all redirects — use for Step 1 where app redirects to IBM SSO. */
function _getFollowRedirects(helper, url) {
    try {
        var msg = _buildMsg(HttpRequestHeader.GET, url);
        msg.setRequestBody("");
        msg.getRequestHeader().setContentLength(0);
        helper.sendAndReceive(msg, true);
        return msg;
    } catch (e) {
        _log("WARNING: _getFollowRedirects failed for " + url + " : " + e);
        // fall back to no-redirect
        try {
            var msg2 = _buildMsg(HttpRequestHeader.GET, url);
            msg2.setRequestBody("");
            msg2.getRequestHeader().setContentLength(0);
            helper.sendAndReceive(msg2, false);
            return msg2;
        } catch (e2) {
            _log("WARNING: _getFollowRedirects fallback also failed: " + e2);
            return _emptyMsg();
        }
    }
}

/** POST without following redirects. */
function _post(helper, url, bodyStr) {
    try {
        var msg = _buildMsg(HttpRequestHeader.POST, url);
        msg.getRequestHeader().setHeader("Content-Type", "application/x-www-form-urlencoded");
        msg.setRequestBody(bodyStr);
        msg.getRequestHeader().setContentLength(msg.getRequestBody().length());
        helper.sendAndReceive(msg, false);
        return msg;
    } catch (e) {
        _log("WARNING: _post failed for " + url + " : " + e);
        return _emptyMsg();
    }
}

/**
 * Return a minimal valid message that won't NPE downstream.
 * Used only when all network attempts fail.
 */
function _emptyMsg() {
    try {
        return _buildMsg(HttpRequestHeader.GET, "https://www.ibm.com/");
    } catch (e) {
        return new HttpMessage();
    }
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
