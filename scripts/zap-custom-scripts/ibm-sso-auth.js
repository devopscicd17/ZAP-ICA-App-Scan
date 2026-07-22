/**
 * ZAP Authentication Script for IBM SSO (IBM Consulting Advantage)
 *
 * Script Type  : Authentication
 * Script Engine: ECMAScript : Graal.js  (ZAP 2.14+ / ghcr.io/zaproxy/zaproxy:stable)
 *
 * Supports two IBM SSO flows:
 *   A. IBM Cloud OIDC / MTFIM  (prepiam.ice.ibmcloud.com) — used by IKS/ROKS-hosted apps
 *   B. IBM w3id SAML2 POST     (w3id.sso.ibm.com)         — used by legacy w3id apps
 *
 * The script auto-detects which flow the app is using by inspecting the initial response.
 *
 * Required ZAP Parameters (authentication.parameters in automation plan):
 *   ICA_APP_URL       — Target ICA application URL
 *   IBM_SSO_LOGIN_URL — (optional) Override IdP endpoint
 *
 * Required User Credentials:
 *   username          — IBM w3id / IBMid email address
 *   password          — IBM w3id / IBMid password
 *
 * CRITICAL GraalVM JS notes:
 *   - Never use HttpRequestHeader.GET/POST/HTTP11 (Java static String constants) —
 *     GraalVM's toUpperCase() NPEs on them. Use plain JS string literals "GET"/"POST"/"HTTP/1.1".
 *   - Always _buildMsg(method, url) — never helper.prepareMessage() + setters.
 *   - ZAP re-encodes & to &amp; in paramsValues — read ICA_APP_URL from System.getenv().
 */

// ---------------------------------------------------------------------------
// Java type imports
// ---------------------------------------------------------------------------
var HttpRequestHeader  = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpMessage        = Java.type('org.parosproxy.paros.network.HttpMessage');
var URI;
try {
    URI = Java.type('org.apache.commons.httpclient.URI');
} catch (e) {
    URI = Java.type('org.apache.commons.httpclient3.URI');
}

// ---------------------------------------------------------------------------
// Public API required by ZAP's Script-based Authentication
// ---------------------------------------------------------------------------

function authenticate(helper, paramsValues, credentials) {
    _log("=== IBM SSO Authentication START ===");

    var username = credentials.getParam("username");
    var password = credentials.getParam("password");

    // Read appUrl from OS env — ZAP re-encodes & to &amp; in paramsValues
    var appUrl = java.lang.System.getenv("ICA_APP_URL")
              || _htmlDecode(_param(paramsValues, "ICA_APP_URL"));

    var ssoLoginUrl = java.lang.System.getenv("IBM_SSO_LOGIN_URL")
                   || _htmlDecode(_param(paramsValues, "IBM_SSO_LOGIN_URL"))
                   || "https://w3id.sso.ibm.com/auth/sps/samlidp2/saml20";

    if (!username || !password) {
        _log("ERROR: username or password is empty");
        return _get(helper, appUrl || "https://www.ibm.com/");
    }
    if (!appUrl) {
        _log("ERROR: ICA_APP_URL is not set");
        return _get(helper, "https://www.ibm.com/");
    }

    _log("User    : " + username);
    _log("App URL : " + appUrl);
    _log("SSO URL : " + ssoLoginUrl);

    try {
        // ------------------------------------------------------------------
        // Step 1 — Fetch the app to discover which SSO flow it uses
        // ------------------------------------------------------------------
        _log("Step 1: Fetching app to detect SSO flow...");
        var initMsg  = _getFollowRedirects(helper, appUrl);
        var initBody = _body(initMsg);
        var initStat = _status(initMsg);
        var finalUrl = _finalUrl(initMsg, appUrl);
        _log("Initial HTTP status: " + initStat + "  Final URL: " + finalUrl);

        // ------------------------------------------------------------------
        // Detect SSO flow from response content and final URL
        // ------------------------------------------------------------------
        _log("Body snippet (first 500): " + initBody.substring(0, 500));

        // Flow A: IBM Cloud OIDC / MTFIM (prepiam.ice.ibmcloud.com or iam.cloud.ibm.com)
        // The app may HTTP-redirect to prepiam, OR return 200 with a JS redirect.
        var jsRedirectUrl = _extractJsRedirect(initBody);
        _log("JS redirect URL found: " + (jsRedirectUrl || "none"));

        if (finalUrl.indexOf("prepiam.ice.ibmcloud.com") >= 0
                || finalUrl.indexOf("iam.cloud.ibm.com") >= 0
                || finalUrl.indexOf("prepiam.") >= 0
                || initBody.indexOf("prepiam.ice.ibmcloud.com") >= 0
                || initBody.indexOf("IBMid") >= 0
                || initBody.indexOf("ibm-login") >= 0
                || (jsRedirectUrl && jsRedirectUrl.indexOf("prepiam") >= 0)
                || (jsRedirectUrl && jsRedirectUrl.indexOf("ibmcloud.com") >= 0)) {
            _log("Detected IBM Cloud OIDC flow (prepiam/IBMid)");
            // Pass the JS redirect URL so _authenticateOIDC can fetch the actual login page
            var oidcStartUrl = (jsRedirectUrl && jsRedirectUrl.match(/^https?:\/\//))
                             ? jsRedirectUrl : finalUrl;
            return _authenticateOIDC(helper, username, password, initMsg, initBody, oidcStartUrl, appUrl);
        }

        // Flow B: w3id SAML2 POST (SAMLRequest hidden field)
        var samlRequest = _extractHiddenField(initBody, "SAMLRequest");
        if (samlRequest) {
            _log("Detected SAML2 POST flow (SAMLRequest found)");
            return _authenticateSAML(helper, username, password, initMsg, initBody, ssoLoginUrl, appUrl);
        }

        // Flow B fallback: app redirected to w3id directly
        if (finalUrl.indexOf("w3id.sso.ibm.com") >= 0) {
            _log("Detected SAML2 flow (redirected to w3id)");
            return _authenticateSAML(helper, username, password, initMsg, initBody, ssoLoginUrl, appUrl);
        }

        // Unknown / no SSO detected (app returned 200 without login page)
        _log("WARNING: No SSO redirect detected (status " + initStat + ") — app may be open or use a different auth method");
        return initMsg;

    } catch (e) {
        _log("EXCEPTION during authentication: " + e);
        if (e.javaException) e.javaException.printStackTrace();
        return _get(helper, appUrl);
    }
}

// ---------------------------------------------------------------------------
// Flow A — IBM Cloud OIDC / MTFIM (prepiam.ice.ibmcloud.com)
// ---------------------------------------------------------------------------
function _authenticateOIDC(helper, username, password, initMsg, initBody, oidcStartUrl, appUrl) {
    _log("OIDC Step A1: Fetching IBM Cloud login page from: " + oidcStartUrl);

    // Fetch the OIDC start URL (prepiam.ice.ibmcloud.com OIDC authorize endpoint).
    // This follows HTTP redirects and should land on the actual HTML login form.
    var loginMsg  = _getFollowRedirects(helper, oidcStartUrl);
    var loginBody = _body(loginMsg);
    var loginUrl  = _finalUrl(loginMsg, oidcStartUrl);
    _log("OIDC login page URL: " + loginUrl + "  status: " + _status(loginMsg));
    _log("Login body snippet: " + loginBody.substring(0, 300));

    // If still no form, try extracting another JS redirect from this page
    if (!_extractFormAction(loginBody)) {
        var jsRedirect2 = _extractJsRedirect(loginBody);
        if (jsRedirect2 && jsRedirect2 !== oidcStartUrl) {
            _log("OIDC A1b: Following secondary JS redirect to: " + jsRedirect2);
            loginMsg  = _getFollowRedirects(helper, jsRedirect2);
            loginBody = _body(loginMsg);
            loginUrl  = _finalUrl(loginMsg, jsRedirect2);
            _log("OIDC A1b final URL: " + loginUrl + "  status: " + _status(loginMsg));
        }
    }

    // Extract the login form action
    var formAction = _extractFormAction(loginBody) || loginUrl;
    if (!formAction.match(/^https?:\/\//)) {
        // Relative URL — resolve against loginUrl origin
        var origin = loginUrl.replace(/(https?:\/\/[^\/]+).*/, "$1");
        formAction = origin + (formAction.charAt(0) === '/' ? '' : '/') + formAction;
    }
    _log("OIDC Step A2: POSTing credentials to: " + formAction);

    // Build the POST body — IBM Cloud login form typically uses 'username'/'password'
    // Extract any hidden fields (state tokens, CSRF, etc.)
    var postBody = "username=" + _encode(username) + "&password=" + _encode(password);
    var hiddenFields = _extractAllHiddenFields(loginBody);
    for (var k in hiddenFields) {
        if (k !== "username" && k !== "password") {
            postBody += "&" + _encode(k) + "=" + _encode(hiddenFields[k]);
        }
    }

    var loginResp = _post(helper, formAction, postBody);
    var loginStat = _status(loginResp);
    var loginRespBody = _body(loginResp);
    _log("OIDC A2 response status: " + loginStat);

    // May need additional redirect/consent steps
    if (loginStat === 302 || loginStat === 303) {
        var loc = _header(loginResp, "Location");
        if (loc) {
            _log("OIDC A3: Following post-login redirect to: " + loc);
            loginResp     = _getFollowRedirects(helper, loc);
            loginRespBody = _body(loginResp);
            _log("OIDC A3 final status: " + _status(loginResp));
        }
    }

    // Verify by fetching the app again
    _log("OIDC A4: Verifying session...");
    var verifyMsg  = _getFollowRedirects(helper, appUrl);
    var verifyUrl  = _finalUrl(verifyMsg, appUrl);
    var verifyStat = _status(verifyMsg);
    _log("Verify status: " + verifyStat + "  URL: " + verifyUrl);

    var authenticated = verifyStat === 200
        && verifyUrl.indexOf("prepiam") < 0
        && verifyUrl.indexOf("iam.cloud.ibm.com") < 0
        && verifyUrl.indexOf("login") < 0;

    if (authenticated) {
        _log("=== OIDC Authentication SUCCESSFUL ===");
    } else {
        _log("WARNING: May not be authenticated — still on login page or unexpected redirect");
    }
    return verifyMsg;
}

// ---------------------------------------------------------------------------
// Flow B — IBM w3id SAML2 POST binding
// ---------------------------------------------------------------------------
function _authenticateSAML(helper, username, password, initMsg, initBody, ssoLoginUrl, appUrl) {
    var samlRequest = _extractHiddenField(initBody, "SAMLRequest");
    var relayState  = _extractHiddenField(initBody, "RelayState");
    var idpAction   = _extractFormAction(initBody) || ssoLoginUrl;
    _log("SAML Step B1: IdP action URL: " + idpAction);

    var loginBody = "username=" + _encode(username) + "&password=" + _encode(password);
    if (samlRequest) loginBody += "&SAMLRequest=" + _encode(samlRequest);
    if (relayState)  loginBody += "&RelayState="  + _encode(relayState);

    _log("SAML Step B2: POSTing credentials to IdP...");
    var loginMsg    = _post(helper, idpAction, loginBody);
    var loginStatus = _status(loginMsg);
    var loginRespBody = _body(loginMsg);
    _log("IdP response status: " + loginStatus);

    if (loginStatus === 302) {
        var location = _header(loginMsg, "Location");
        if (location) {
            _log("Following IdP redirect to: " + location);
            loginMsg      = _getFollowRedirects(helper, location);
            loginRespBody = _body(loginMsg);
        }
    }

    var samlResponse = _extractHiddenField(loginRespBody, "SAMLResponse");
    var relayState2  = _extractHiddenField(loginRespBody, "RelayState");
    var acsUrl       = _extractFormAction(loginRespBody) || (appUrl + "/saml/acs");

    if (!samlResponse) {
        _log("ERROR: No SAMLResponse found — check credentials or IdP URL");
        return loginMsg;
    }

    _log("SAML Step B3: POSTing SAMLResponse to SP ACS: " + acsUrl);
    var acsBody = "SAMLResponse=" + _encode(samlResponse);
    if (relayState2) acsBody += "&RelayState=" + _encode(relayState2);
    var acsMsg = _post(helper, acsUrl, acsBody);
    _log("ACS response status: " + _status(acsMsg));

    _log("SAML Step B4: Verifying session...");
    var verifyMsg  = _getFollowRedirects(helper, appUrl);
    var verifyBody = _body(verifyMsg);
    var stillOnLogin = verifyBody.toLowerCase().indexOf("w3id.sso.ibm.com") >= 0
                    || verifyBody.toLowerCase().indexOf("samlrequest") >= 0;

    if (_status(verifyMsg) === 200 && !stillOnLogin) {
        _log("=== SAML Authentication SUCCESSFUL ===");
    } else {
        _log("WARNING: Post-auth check suggests login may have failed");
    }
    return verifyMsg;
}

function getRequiredParamsNames() { return ["ICA_APP_URL"]; }
function getOptionalParamsNames()  { return ["IBM_SSO_LOGIN_URL"]; }
function getCredentialsParamsNames() { return ["username", "password"]; }

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

/**
 * Build a fresh HttpMessage using the 3-arg HttpRequestHeader constructor.
 *
 * CRITICAL: In GraalVM JS, HttpRequestHeader.GET / .POST / .HTTP11 are Java
 * String objects. Passing them to the constructor causes toUpperCase() to NPE.
 * Always pass plain JS string literals: "GET", "POST", "HTTP/1.1".
 */
function _buildMsg(method, url) {
    var cleanUrl = _htmlDecode(String(url));
    var uri      = new URI(cleanUrl, false);
    // "HTTP/1.1" is a plain JS string literal — NOT HttpRequestHeader.HTTP11
    var header   = new HttpRequestHeader(String(method), uri, "HTTP/1.1");
    return new HttpMessage(header);
}

function _get(helper, url) {
    try {
        var msg = _buildMsg("GET", url);
        msg.setRequestBody("");
        msg.getRequestHeader().setContentLength(0);
        helper.sendAndReceive(msg, false);
        return msg;
    } catch (e) {
        _log("WARNING: _get failed: " + e);
        return _emptyMsg();
    }
}

function _getFollowRedirects(helper, url) {
    try {
        var msg = _buildMsg("GET", url);
        msg.setRequestBody("");
        msg.getRequestHeader().setContentLength(0);
        helper.sendAndReceive(msg, true);
        return msg;
    } catch (e) {
        _log("WARNING: _getFollowRedirects failed for " + url + " : " + e);
        try {
            var msg2 = _buildMsg("GET", url);
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

function _post(helper, url, bodyStr) {
    try {
        var msg = _buildMsg("POST", url);
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

function _emptyMsg() {
    try { return _buildMsg("GET", "https://www.ibm.com/"); } catch (e) { return new HttpMessage(); }
}

// ---------------------------------------------------------------------------
// Response helpers
// ---------------------------------------------------------------------------

function _body(msg) {
    try { var b = msg.getResponseBody(); return b ? b.toString() : ""; } catch (e) { return ""; }
}

function _status(msg) {
    try { var h = msg.getResponseHeader(); return h ? h.getStatusCode() : 0; } catch (e) { return 0; }
}

function _header(msg, name) {
    try { var h = msg.getResponseHeader(); return h ? h.getHeader(name) : null; } catch (e) { return null; }
}

/** Return the final URL after redirect-following (from request header). */
function _finalUrl(msg, fallback) {
    try {
        var uri = msg.getRequestHeader().getURI();
        return uri ? uri.toString() : (fallback || "");
    } catch (e) { return fallback || ""; }
}

// ---------------------------------------------------------------------------
// HTML/form parsing helpers
// ---------------------------------------------------------------------------

function _extractHiddenField(html, name) {
    var re1 = new RegExp('name=["\']' + name + '["\'][^>]*?value=["\']([^"\']*)["\']', 'i');
    var m = re1.exec(html);
    if (m) return m[1];
    var re2 = new RegExp('value=["\']([^"\']*)["\'][^>]*?name=["\']' + name + '["\']', 'i');
    m = re2.exec(html);
    return m ? m[1] : null;
}

/** Extract all hidden input fields as a key→value map. */
function _extractAllHiddenFields(html) {
    var result = {};
    var re = /<input[^>]+type=["']hidden["'][^>]*>/gi;
    var match;
    while ((match = re.exec(html)) !== null) {
        var tag  = match[0];
        var name  = _attrVal(tag, "name");
        var value = _attrVal(tag, "value");
        if (name) result[name] = value || "";
    }
    return result;
}

function _attrVal(tag, attr) {
    var re = new RegExp(attr + '=["\']([^"\']*)["\']', 'i');
    var m  = re.exec(tag);
    return m ? m[1] : null;
}

function _extractFormAction(html) {
    var m = /<form[^>]+action=["']([^"']+)["']/i.exec(html);
    return m ? _htmlDecode(m[1]) : null;
}

/**
 * Extract a client-side JavaScript redirect URL from an HTML page body.
 * IBM Cloud OIDC apps sometimes return HTTP 200 with window.location= or
 * meta-refresh instead of a proper HTTP 302 redirect.
 */
function _extractJsRedirect(html) {
    if (!html) return null;
    var patterns = [
        /window\.location(?:\.href)?\s*=\s*["']([^"']+)["']/i,
        /location\.replace\s*\(\s*["']([^"']+)["']\s*\)/i,
        /location\.href\s*=\s*["']([^"']+)["']/i,
        /<meta[^>]+http-equiv=["']refresh["'][^>]+content=["'][^;]*;\s*url=([^"']+)["']/i,
        /<meta[^>]+content=["'][^;]*;\s*url=([^"']+)["'][^>]+http-equiv=["']refresh["']/i
    ];
    for (var i = 0; i < patterns.length; i++) {
        var m = patterns[i].exec(html);
        if (m && m[1] && m[1].match(/^https?:\/\//)) {
            return _htmlDecode(m[1].trim());
        }
    }
    return null;
}

function _encode(str) {
    return java.net.URLEncoder.encode(String(str), "UTF-8");
}

function _param(paramsValues, key) {
    try { return paramsValues.get(key) || null; } catch (e) { return null; }
}

function _htmlDecode(str) {
    if (!str) return str;
    return String(str)
        .replace(/&amp;/g,  '&')
        .replace(/&lt;/g,   '<')
        .replace(/&gt;/g,   '>')
        .replace(/&quot;/g, '"')
        .replace(/&#39;/g,  "'");
}

function _log(msg) {
    java.lang.System.out.println("[IBM-SSO-Auth] " + msg);
}

// Made with Bob
