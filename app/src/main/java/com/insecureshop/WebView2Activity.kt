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

        // FIX: Validate extra_intent before processing to prevent intent redirection attacks
        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
        if (extraIntent != null) {
            // FIX: Verify the target component belongs to this application or trusted packages
            if (isIntentSafe(extraIntent)) {
                startActivity(extraIntent)
            } else {
                Log.w("WebView2Activity", "Blocked unsafe intent redirection")
                Toast.makeText(this, "Invalid intent provided", Toast.LENGTH_SHORT).show()
            }
            finish()
            return
        }

        // FIX: Validate intent action to ensure only expected actions are processed
        if (intent.action != Intent.ACTION_VIEW && intent.action != Intent.ACTION_SEND) {
            Log.w("WebView2Activity", "Blocked unexpected intent action")
            finish()
            return
        }

        val webview = findViewById<WebView>(R.id.webview) as WebView

        // FIX: Disable JavaScript to prevent code injection (enable only if absolutely necessary)
        webview.settings.javaScriptEnabled = false
        webview.settings.loadWithOverviewMode = true
        webview.settings.useWideViewPort = true
        // FIX: Disable universal file access to prevent file system exposure
        webview.settings.allowUniversalAccessFromFileURLs = false
        // FIX: Disable file access to prevent accessing local files
        webview.settings.allowFileAccess = false
        // FIX: Disable content access to prevent content provider exploitation
        webview.settings.allowContentAccess = false
// FIX: Added validation method to verify extra_intent targets trusted components only
    private fun isIntentSafe(extraIntent: Intent): Boolean {
        return try {
            val targetPackage = extraIntent.component?.packageName
            
            // FIX: Only allow intents targeting this application's package
            if (targetPackage != null && targetPackage == packageName) {
                return true
            }
            
            // FIX: Optionally allow explicitly trusted packages (add as needed)
            val trustedPackages = listOf<String>() // Add trusted packages if needed
            targetPackage in trustedPackages
        } catch (e: Exception) {
            // FIX: Log parsing exceptions without exposing sensitive details
// FIX: Added validation method to restrict URL schemes and implement domain allowlist
    private fun isUrlSafe(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        
        return try {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.lowercase()
            
            // FIX: Only allow HTTPS and HTTP schemes to prevent javascript:, file://, content:// attacks
            if (scheme !in listOf("https", "http")) {
                return false
            }
            
            // FIX: Implement domain allowlist for additional security
            val allowedDomains = listOf("trusted-domain.com", "company.com", "insecureshop.com")
            val host = uri.host?.lowercase()
            
            // FIX: Verify host matches one of the allowed domains
            if (host == null) return false
            
            // FIX: Prevent subdomain bypass attacks by ensuring exact match or proper subdomain structure
            allowedDomains.any { host == it || host.endsWith(".$it") }
        } catch (e: Exception) {
            // FIX: Log parsing exceptions without exposing sensitive exception details
            Log.e("WebView2Activity", "URL parsing failed")
            false
        }
    }
