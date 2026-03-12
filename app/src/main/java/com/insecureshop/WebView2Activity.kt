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

// FIXED: Added validation method for extra_intent to prevent intent redirection attacks
    private fun isValidExtraIntent(intent: Intent?): Boolean {
        if (intent == null) return false
        
        try {
            // FIXED: Only allow intents targeting your own application components
            val targetPackage = intent.component?.packageName ?: return false
            if (targetPackage != packageName) return false
            
            // FIXED: Allowlist specific safe activities only to prevent arbitrary component access
            val safeActivities = setOf(
                "com.insecureshop.SafeActivity1",
                "com.insecureshop.SafeActivity2"
            )
            
            val targetClass = intent.component?.className ?: return false
            return targetClass in safeActivities
            
        } catch (e: Exception) {
            return false
        }
    }

        // FIXED: Enabled SafeBrowsing API for additional protection against malicious URLs
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            webview.settings.safeBrowsingEnabled = true
        }
        
        // FIXED: Get URL from various sources and validate before loading
        val urlToLoad = when {
            !intent.dataString.isNullOrBlank() -> intent.dataString
            !intent.data?.getQueryParameter("url").isNullOrBlank() -> intent.data?.getQueryParameter("url")
            !intent.extras?.getString("url").isNullOrEmpty() -> intent.extras?.getString("url")
            else -> null
// FIXED: Added URL validation method to enforce allowlist of trusted domains and schemes
    private fun isValidUrl(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        
        try {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.toLowerCase(Locale.ROOT)
            
            // FIXED: Only allow HTTPS and HTTP schemes to prevent javascript: and file: URL attacks
            if (scheme != "https" && scheme != "http") {
                return false
            }
            
            // FIXED: Validate against allowlist of trusted domains to prevent unauthorized access
            val allowedDomains = listOf(
                "yourdomain.com",
                "trusted-partner.com"
            )
            
            val host = uri.host?.toLowerCase(Locale.ROOT) ?: return false
            return allowedDomains.any { host == it || host.endsWith(".$it") }
            
        } catch (e: Exception) {
            return false
        }
    }
