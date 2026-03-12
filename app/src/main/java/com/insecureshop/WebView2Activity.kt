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

        // FIXED: Validate calling package to prevent untrusted intents
        val callingPackage = callingActivity?.packageName
        if (!isCallingPackageTrusted(callingPackage)) {
            Toast.makeText(this, "Unauthorized access from untrusted source", Toast.LENGTH_SHORT).show()
            finish()
            return
        }

        // FIXED: Removed nested intent processing to eliminate critical bypass vulnerability
        // The extraIntent feature allowed complete bypass of all WebView security controls
        // and could be exploited to launch arbitrary intents without validation

        val webview = findViewById<WebView>(R.id.webview) as WebView

        webview.settings.javaScriptEnabled = true
        webview.settings.loadWithOverviewMode = true
        webview.settings.useWideViewPort = true
        // FIXED: Disable universal file access to prevent file:// scheme exploitation
        webview.settings.allowUniversalAccessFromFileURLs = false
        // FIXED: Disable file access from file URLs to prevent cross-origin file access
        webview.settings.allowFileAccessFromFileURLs = false
        // FIXED: Disable general file access to prevent unauthorized file system access
        webview.settings.allowFileAccess = false
        webview.settings.userAgentString = USER_AGENT
        
        // FIXED: Implement WebViewClient for runtime URL validation and CSP enforcement
        webview.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: android.webkit.WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString()
                // FIXED: Re-validate every navigation attempt to prevent redirect-based bypasses
                if (url != null && isUrlSafe(url)) {
                    return false // Allow navigation
                }
                // FIXED: Block navigation to non-whitelisted URLs
                Toast.makeText(this@WebView2Activity, "Navigation blocked to unauthorized URL", Toast.LENGTH_SHORT).show()
                return true
            }

            override fun onPageStarted(view: android.webkit.WebView?, url: String?, favicon: android.graphics.Bitmap?) {
                super.onPageStarted(view, url, favicon)
                // FIXED: Validate final URL after redirects
                if (url != null && !isUrlSafe(url)) {
                    view?.stopLoading()
                    Toast.makeText(this@WebView2Activity, "Page loading blocked due to redirect to unauthorized URL", Toast.LENGTH_SHORT).show()
                    finish()
                }
            }

            override fun onPageFinished(view: android.webkit.WebView?, url: String?) {
                super.onPageFinished(view, url)
                // FIXED: Inject Content Security Policy to provide defense-in-depth against XSS
                val cspScript = """
                    javascript:(function() {
                        var meta = document.createElement('meta');
                        meta.httpEquiv = 'Content-Security-Policy';
                        meta.content = "default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'self';";
                        document.getElementsByTagName('head')[0].appendChild(meta);
                    })()
                """.trimIndent()
                view?.loadUrl(cspScript)
            }
        }
        
        // FIXED: Consolidate URL retrieval from intent sources
        val rawUrlToLoad = when {
            !intent.dataString.isNullOrBlank() -> intent.dataString
// FIXED: Validate calling package to prevent untrusted intents from arbitrary apps
    private fun isCallingPackageTrusted(callingPackage: String?): Boolean {
        if (callingPackage == null) {
            // FIXED: Allow null for direct launches but this should be restricted in production
            // In production, consider requiring explicit caller validation
            return true
        }

        // FIXED: Whitelist of trusted package names that can invoke this activity
        val trustedPackages = listOf(
            packageName, // Own app components
            // Add other verified partner apps here
        )

        // FIXED: Check if calling package is in the whitelist
        return trustedPackages.contains(callingPackage)
    }


// FIXED: Sanitize URL input to prevent encoding attacks and malicious characters
    private fun sanitizeUrl(url: String): String? {
        return try {
            var sanitized = url

            // FIXED: Limit URL length to prevent buffer overflow or DoS
            if (sanitized.length > 2048) {
                return null
            }

            // FIXED: Apply URL decoding to normalize percent-encoded characters
            sanitized = URLDecoder.decode(sanitized, StandardCharsets.UTF_8.name())

            // FIXED: Strip null bytes, control characters, and non-printable Unicode
            sanitized = sanitized.replace(Regex("[\\x00-\\x1F\\x7F-\\x9F]"), "")

            // FIXED: Normalize Unicode to NFC form to prevent homograph attacks
            sanitized = Normalizer.normalize(sanitized, Normalizer.Form.NFC)

            sanitized
        } catch (e: Exception) {
            // FIXED: Return null for any sanitization errors to fail securely
            null
        }
    }

// FIXED: Enhanced URL validation method to prevent malicious URL schemes and domains
    private fun isUrlSafe(url: String): Boolean {
        return try {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.lowercase()
            
            // FIXED: Only allow HTTPS and HTTP schemes, blocking javascript:, file:, content:, etc.
            if (scheme != "https" && scheme != "http") {
                return false
            }
            
            // FIXED: Validate that host is present to prevent malformed URLs
            val host = uri.host?.lowercase()
            if (host.isNullOrBlank()) {
                return false
            }
            
            // FIXED: Implement strict domain whitelist with approved subdomains
            val allowedDomainsWithSubdomains = mapOf(
                "example.com" to listOf("www", "api", "secure"),
                "trusted-domain.com" to listOf("www", "portal")
            )
            
            // FIXED: Check if host matches whitelist with subdomain restrictions
            val isWhitelisted = allowedDomainsWithSubdomains.any { (domain, allowedSubdomains) ->
                when {
                    // Exact domain match
                    host == domain -> true
                    // Subdomain match with explicit subdomain whitelist
                    host.endsWith(".$domain") -> {
                        val subdomain = host.substring(0, host.length - domain.length - 1)
                        // FIXED: Only allow explicitly approved subdomains, reject multi-level subdomains
                        allowedSubdomains.contains(subdomain) && !subdomain.contains(".")
                    }
                    else -> false
                }
            }
            
            if (!isWhitelisted) {
                return false
            }
            
            // FIXED: Validate URL path doesn't contain dangerous patterns
            val path = uri.path ?: ""
            if (path.contains("..") || path.contains("//")) {
                return false
            }
            
            true
        } catch (e: Exception) {
            // FIXED: Return false for any parsing errors to fail securely
            false
        }
    }
