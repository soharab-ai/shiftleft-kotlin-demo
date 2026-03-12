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

        // FIX: Remove extra intent handling entirely to prevent accepting serialized intents from external sources
        // This eliminates the vulnerability of accepting arbitrary intent objects with manipulated flags
        val extraIntent = intent.getParcelableExtra<Intent>("extra_intent")
        if (extraIntent != null) {
            Log.w("WebView2Activity", "Blocked untrusted extra_intent - parceled intents from external sources are not accepted")
            finish()
            return
        }

        val webview = findViewById<WebView>(R.id.webview) as WebView

        // FIX: Disable JavaScript to prevent code injection attacks
        webview.settings.javaScriptEnabled = false
        webview.settings.loadWithOverviewMode = true
        webview.settings.useWideViewPort = true
        // FIX: Disable file access to prevent unauthorized file system access
        webview.settings.allowUniversalAccessFromFileURLs = false
        webview.settings.allowFileAccessFromFileURLs = false
        webview.settings.allowFileAccess = false
        webview.settings.userAgentString = USER_AGENT
        
        // FIX: Implement runtime URL revalidation for all navigation attempts
        webview.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                val navigationUrl = request.url.toString()
                // FIX: Validate every navigation attempt with certificate pinning
                if (isUrlSafeWithCertificatePinning(navigationUrl)) {
                    return false // Allow navigation
                } else {
                    Log.w("WebView2Activity", "Blocked navigation to untrusted URL: $navigationUrl")
                    Toast.makeText(this@WebView2Activity, "Navigation blocked: untrusted URL", Toast.LENGTH_SHORT).show()
                    view.stopLoading()
                    return true // Block navigation
                }
            }
        }
        
        // FIX: Validate URL from all intent sources before loading
        val urlToLoad = when {
            !intent.dataString.isNullOrBlank() -> intent.dataString
            !intent.data?.getQueryParameter("url").isNullOrBlank() -> 
                intent.data?.getQueryParameter("url")
            !intent.extras?.getString("url").isNullOrEmpty() -> 
                intent.extras?.getString("url")
            else -> null
        }
        
        // FIX: Apply strict URL validation with certificate pinning
        if (isUrlSafeWithCertificatePinning(urlToLoad)) {
            webview.loadUrl(urlToLoad!!)
        } else {
            // FIX: Log security event and show user-friendly error
            Log.w("WebView2Activity", "Blocked untrusted URL: $urlToLoad")
// FIX: Replace static allowlist with dynamic certificate pinning validation
    private fun isUrlSafeWithCertificatePinning(url: String?): Boolean {
        if (url.isNullOrBlank()) return false
        
        try {
            val uri = Uri.parse(url)
            val scheme = uri.scheme?.lowercase()
            val host = uri.host?.lowercase()
            
            // FIX: Only allow HTTPS scheme
            if (scheme != "https") return false
            
            // FIX: Certificate pinning map - domain to expected SHA-256 public key hashes
            val certificatePins = mapOf(
                "yourdomain.com" to listOf(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // Primary certificate pin
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="  // Backup certificate pin
                ),
                "www.yourdomain.com" to listOf(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="
                ),
                "trusted.example.com" to listOf(
                    "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
                    "DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD="
                )
            )
            
            // FIX: Verify host is in the certificate pins map
            if (host == null || !certificatePins.containsKey(host)) {
                Log.w("WebView2Activity", "Host not in certificate pinning allowlist: $host")
                return false
            }
            
            // FIX: Establish HTTPS connection and verify certificate pin
            val connection = URL(url).openConnection() as HttpsURLConnection
            connection.connect()
            
            val certificates = connection.serverCertificates
            if (certificates.isEmpty()) return false
            
            // FIX: Compute SHA-256 hash of the public key
            val publicKey = certificates[0].publicKey.encoded
            val digest = MessageDigest.getInstance("SHA-256")
            val hash = digest.digest(publicKey)
            val pin = android.util.Base64.encodeToString(hash, android.util.Base64.NO_WRAP)
            
            connection.disconnect()
            
            // FIX: Compare against expected pins
// FIX: Added sanitization method for log entries to prevent log injection
    private fun sanitizeLogEntry(input: String?): String {
        if (input == null) return "null"
        // Remove newlines, carriage returns, and other control characters
        return input.replace(Regex("[\\r\\n\\t]"), "_")
            .replace(Regex("[^\\p{Print}]"), "")
            .take(200) // Limit length to prevent log flooding
    }
