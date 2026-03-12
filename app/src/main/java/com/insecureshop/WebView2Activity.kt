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
        
        // FIXED: Validate calling package to ensure only trusted applications can pass data
        val callingPackage = callingActivity?.packageName
        val trustedCallers = listOf("com.insecureshop", "com.trusted.app")
        if (callingPackage != null && callingPackage !in trustedCallers) {
            Log.w("WebView2Activity", "Untrusted caller: ${sanitizeForLog(callingPackage)}")
            finish()
            return
        }
        
        setContentView(R.layout.activity_webview)
        title = getString(R.string.webview)

        // FIXED: Validate extra_intent component before processing to prevent arbitrary activity launching
        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
        if (extraIntent != null) {
            val allowedComponents = setOf(
                ComponentName(this, "com.insecureshop.SomeActivity")
                // Add other trusted components as needed
            )
            if (extraIntent.component != null && extraIntent.component in allowedComponents) {
                startActivity(extraIntent)
            } else {
                Log.w("WebView2Activity", "Blocked untrusted intent component: ${sanitizeForLog(extraIntent.component?.toString())}")
            }
            finish()
            return
        }

        // FIXED: Validate Intent action and URI scheme at Intent level before processing
        if (intent.action != Intent.ACTION_VIEW && intent.action != null) {
            Log.w("WebView2Activity", "Invalid intent action: ${sanitizeForLog(intent.action)}")
            finish()
            return
        }

        val intentScheme = intent.data?.scheme
        if (intentScheme != null && intentScheme !in listOf("https", "http")) {
            Log.w("WebView2Activity", "Blocked dangerous URI scheme: ${sanitizeForLog(intentScheme)}")
            finish()
            return
        }

        val webview = findViewById<WebView>(R.id.webview) as WebView

        webview.settings.javaScriptEnabled = true
        webview.settings.loadWithOverviewMode = true
        webview.settings.useWideViewPort = true
        // FIXED: Disable dangerous file access settings to prevent local file system access
        webview.settings.allowUniversalAccessFromFileURLs = false
        webview.settings.allowFileAccess = false
        webview.settings.userAgentString = USER_AGENT
        
        // FIXED: Implement WebChromeClient to monitor CSP violations for defense-in-depth
        webview.webChromeClient = object : WebChromeClient() {
            override fun onConsoleMessage(message: ConsoleMessage?): Boolean {
                // Monitor for CSP violations
                if (message?.messageLevel() == ConsoleMessage.MessageLevel.ERROR) {
                    Log.w("WebView2Activity", "CSP Violation: ${sanitizeForLog(message.message())}")
                }
                return true
            }
        }
        
        // FIXED: Implement WebViewClient for runtime URL validation and navigation control
        webview.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView?, request: WebResourceRequest?): Boolean {
                val url = request?.url?.toString()
                return if (isUrlSafe(url)) {
                    false // Allow navigation
                } else {
// FIXED: Enhanced whitelist-based URL validation with parameter sanitization to prevent code injection
private fun isUrlSafe(url: String?): Boolean {
    if (url.isNullOrBlank()) return false
    
    return try {
        val uri = Uri.parse(url)
        val scheme = uri.scheme?.lowercase()
        val host = uri.host?.lowercase()
        
        // FIXED: Only allow HTTPS scheme to prevent javascript:, file://, and data: scheme attacks
        val allowedSchemes = listOf("https")
        
        // FIXED: Whitelist of trusted domains - configure based on application requirements
        val allowedHosts = listOf(
            "trusted-domain.com",
            "www.trusted-domain.com"
            // Add additional trusted domains as needed
        )
        
        // FIXED: Validate both scheme and host are in whitelists
        if (scheme !in allowedSchemes || host !in allowedHosts) {
            return false
        }
        
        // FIXED: Validate query parameters to prevent encoded malicious payloads
        val queryParams = uri.queryParameterNames
        val dangerousParams = listOf("javascript", "eval", "onerror", "onload")
        if (queryParams.any { param -> 
            dangerousParams.any { dangerous -> param.lowercase().contains(dangerous) }
        }) {
            Log.w("WebView2Activity", "Dangerous query parameter detected")
            return false
        }

        // FIXED: Check for encoded payloads in the full URL
        val fullUrl = url.lowercase()
        if (fullUrl.contains("%3cscript") || fullUrl.contains("<script") || 
            fullUrl.contains("javascript:")) {
            return false
        }
        
        // FIXED: Return true only if all validations pass
// FIXED: Sanitize input before logging to prevent log injection attacks
private fun sanitizeForLog(input: String?): String {
    if (input == null) return "null"
    // FIXED: Remove newlines, carriage returns, and tabs to prevent log forging
    return input.replace(Regex("[\\r\\n\\t]"), "_")
}
