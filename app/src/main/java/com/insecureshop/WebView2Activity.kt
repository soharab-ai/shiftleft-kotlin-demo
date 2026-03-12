package com.insecureshop

import android.content.Intent
import android.os.Bundle
import android.webkit.WebView
import android.app.Activity
import kotlinx.android.synthetic.main.activity_product_list.*


class WebView2Activity : Activity() {

    val USER_AGENT =
        "Mozilla/5.0 (Linux; Android 4.1.1; Galaxy Nexus Build/JRO03C) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/43.0.2357.65 Mobile Safari/537.36"

override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_webview)
        title = getString(R.string.webview)

        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
        if (extraIntent != null) {
            // FIX: Validate caller signature and component name before starting intent
            if (!validateCallerIntent(extraIntent)) {
                Log.w("WebView2Activity", "Blocked untrusted extra_intent from unauthorized caller")
                Toast.makeText(this, "Unauthorized intent source", Toast.LENGTH_SHORT).show()
                finish()
                return
            }
            startActivity(extraIntent)
            finish()
            return
        }

        val webview = findViewById<WebView>(R.id.webview) as WebView

        webview.settings.javaScriptEnabled = true
        webview.settings.loadWithOverviewMode = true
        webview.settings.useWideViewPort = true
        // FIX: Disable dangerous file access settings to prevent file:// URL exploitation
        webview.settings.allowUniversalAccessFromFileURLs = false
        webview.settings.allowFileAccess = false
        // FIX: Enable SafeBrowsing for runtime threat detection
        webview.settings.safeBrowsingEnabled = true
        webview.settings.userAgentString = USER_AGENT
        
        // FIX: Explicitly remove default JavaScript interfaces to prevent bridge attacks
        webview.removeJavascriptInterface("searchBoxJavaBridge_")
        webview.removeJavascriptInterface("accessibility")
        webview.removeJavascriptInterface("accessibilityTraversal")
        
        // FIX: Implement WebViewClient with enhanced security validation
        webview.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString()
                return if (isUrlSafe(url)) {
                    false // Allow navigation
                } else {
                    Log.w("WebView2Activity", "Blocked navigation to unsafe URL: $url")
                    true // Block navigation
                }
            }
            
            // FIX: Inject Content Security Policy headers to prevent XSS
            override fun shouldInterceptRequest(view: WebView?, request: WebResourceRequest?): WebResourceResponse? {
                val response = super.shouldInterceptRequest(view, request)
                if (response != null) {
                    val headers = mutableMapOf<String, String>()
                    headers["Content-Security-Policy"] = "default-src 'none'; script-src 'self' https://cdn.trustedpartner.com; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none';"
                    return WebResourceResponse(
                        response.mimeType,
                        response.encoding,
                        response.data
                    ).apply {
                        responseHeaders = headers
                    }
                }
                return response
            }
            
// FIX: Validate caller signature and component name to prevent malicious intent injection
    private fun validateCallerIntent(extraIntent: Intent): Boolean {
        try {
            // Get calling activity or referrer information
            val callingActivity = callingActivity
            val referrer = referrer
            
            val callingPackage = when {
                callingActivity != null -> callingActivity.packageName
                referrer != null -> referrer.host
                else -> {
                    Log.w("WebView2Activity", "Unable to determine caller identity")
                    return false
                }
            }
            
            // FIX: Verify calling package is in trusted allowlist
            val trustedPackages = listOf(
                "com.insecureshop",  // Same app package
                "com.trustedpartner.app"
            )
            
            if (callingPackage !in trustedPackages) {
                Log.w("WebView2Activity", "Caller package not in allowlist: $callingPackage")
                return false
            }
            
            // FIX: Verify package signature matches expected trusted signatures
            val packageInfo = packageManager.getPackageInfo(
                callingPackage,
                PackageManager.GET_SIGNATURES
            )
            
            val signatures = packageInfo.signatures
            val trustedSignatureHashes = listOf(
                // Add SHA-256 hashes of trusted application certificates here
                "EXPECTED_SIGNATURE_HASH_1",
                "EXPECTED_SIGNATURE_HASH_2"
            )
            
            val signatureValid = signatures.any { signature ->
                val signatureHash = computeSignatureHash(signature)
                trustedSignatureHashes.contains(signatureHash)
            }
            
            if (!signatureValid) {
                Log.w("WebView2Activity", "Caller signature verification failed for: $callingPackage")
// FIX: Compute SHA-256 hash of application signature for verification
    private fun computeSignatureHash(signature: Signature): String {
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val digest = md.digest(signature.toByteArray())
            return Base64.encodeToString(digest, Base64.NO_WRAP)
        } catch (e: Exception) {
            Log.e("WebView2Activity", "Signature hash computation failed", e)
            return ""
        }
    }

// FIX: Sanitize URL to prevent encoding bypasses, fragments, and injection attacks
    private fun sanitizeUrl(url: String?): String? {
        if (url.isNullOrBlank()) return null
        
        try {
            var sanitized = url.trim()
            
            // FIX: Iteratively decode URL to prevent double/triple encoding bypasses (max 3 iterations)
            var previousDecoded = sanitized
            for (i in 1..3) {
                val decoded = Uri.decode(sanitized)
                if (decoded == previousDecoded) break
                previousDecoded = decoded
                sanitized = decoded
            }
            
            // FIX: Check for null bytes and control characters
            if (sanitized.contains("\u0000") || sanitized.any { it.isISOControl() }) {
                Log.w("WebView2Activity", "URL contains null bytes or control characters")
                return null
            }
            
            // FIX: Parse URI and validate components
            val uri = Uri.parse(sanitized)
            
            // FIX: Strip fragment identifier to prevent hash-based attacks
            val scheme = uri.scheme?.toLowerCase(Locale.ROOT) ?: return null
            val host = uri.host?.toLowerCase(Locale.ROOT) ?: return null
            val port = uri.port
            val path = uri.path ?: ""
            
            // FIX: Reject non-standard ports (only allow 443 for HTTPS)
            if (port != -1 && port != 443) {
                Log.w("WebView2Activity", "Non-standard port detected: $port")
                return null
            }
            
            // FIX: Detect homograph attacks using Unicode normalization
            val asciiHost = java.net.IDN.toASCII(host)
            
            // FIX: Validate path doesn't contain suspicious patterns
            val pathPattern = Regex("^[a-zA-Z0-9/_.-]*$")
            if (!pathPattern.matches(path)) {
                Log.w("WebView2Activity", "Path contains suspicious characters")
                return null
            }
            
            // FIX: Reconstruct clean URL without fragment and query parameters that could contain injection
            val cleanUrl = Uri.Builder()
// FIX: Enhanced URL validation with strict allowlist and subdomain verification
    private fun isUrlSafe(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        
        try {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.toLowerCase(Locale.ROOT)
            
            // FIX: Only allow HTTPS protocol to prevent javascript:, file:, data: attacks
            if (scheme != "https") {
                Log.w("WebView2Activity", "Blocked non-HTTPS scheme: $scheme")
                return false
            }
            
            // FIX: Get normalized host
            val host = uri.host?.toLowerCase(Locale.ROOT) ?: return false
            
            // FIX: Split hostname into components for strict validation
            val hostParts = host.split(".")
            
            // FIX: Reject hostnames with too many segments (potential bypass attempts)
            if (hostParts.size > 4) {
                Log.w("WebView2Activity", "Hostname has too many segments: $host")
                return false
            }
            
            // FIX: Validate each hostname segment format
            val segmentPattern = Regex("^[a-z0-9-]{1,63}$")
            if (!hostParts.all { segmentPattern.matches(it) }) {
                Log.w("WebView2Activity", "Invalid hostname segment format: $host")
                return false
            }
            
            // FIX: Define strict allowlist with exact domain and approved subdomain patterns
            val allowedDomains = mapOf(
                "example.com" to listOf("www", "api", "cdn"),
                "trustedpartner.com" to listOf("www", "secure")
            )
            
            // FIX: Extract base domain (last 2 components)
            if (hostParts.size < 2) return false
            val baseDomain = "${hostParts[hostParts.size - 2]}.${hostParts[hostParts.size - 1]}"
            
            // FIX: Check if base domain is in allowlist
            if (baseDomain !in allowedDomains.keys) {
                Log.w("WebView2Activity", "Base domain not in allowlist: $baseDomain")
                return false
            }
            
            // FIX: For exact domain match (no subdomain)
            if (host == baseDomain) {
                return true
            }
            
            // FIX: For subdomain, validate against approved subdomain patterns
            val allowedSubdomains = allowedDomains[baseDomain] ?: emptyList()
            
            // Extract subdomain part
            val subdomainParts = hostParts.dropLast(2)
            
            // FIX: Only allow single-level subdomains from approved list
            if (subdomainParts.size == 1 && subdomainParts[0] in allowedSubdomains) {
                return true
            }
            
            Log.w("WebView2Activity", "Subdomain not in allowlist: $host")
            return false
            
        } catch (e: Exception) {
            Log.e("WebView2Activity", "URL validation error", e)
            return false
        }
    }
