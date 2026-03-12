package com.insecureshop.contentProvider

import android.content.ContentProvider
import android.content.ContentValues
import android.content.UriMatcher
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import com.insecureshop.util.Prefs


class InsecureshopFileProvider : ContentProvider() {

    companion object {
        var uriMatcher: UriMatcher? = null
        const val URI_CODE: Int = 100
    // Whitelist of allowed base paths initialized during onCreate (Mitigation Note #2)
    private var allowedBasePaths: Set<String> = emptySet()

override fun onCreate(): Boolean {
        // Enhanced initialization with authority validation (Mitigation Note #6)
        val providerInfo: ProviderInfo? = context?.packageManager?.resolveContentProvider(
            "com.insecureshop.file_provider", 0
        )
        val expectedAuthority = "com.insecureshop.file_provider"
        if (providerInfo?.authority != expectedAuthority) {
            throw IllegalStateException("Provider authority mismatch. Security risk detected.")
        }
        
        uriMatcher = UriMatcher(UriMatcher.NO_MATCH)
        // Using validated authority instead of hardcoded string
        uriMatcher?.addURI(expectedAuthority, "insecure", URI_CODE)
        
        // Programmatic validation to prevent root path configuration (Mitigation Note #2)
        initializeAllowedPaths()
        return true
    // Added method to initialize and validate allowed paths (Mitigation Note #2)
    private fun initializeAllowedPaths() {
        val ctx = context ?: throw IllegalStateException("Context is null during provider initialization")
        
        // Define whitelist of allowed base paths - restricted to app-specific directories only
        allowedBasePaths = mutableSetOf<String>().apply {
            ctx.filesDir?.canonicalPath?.let { add(it) }
            ctx.cacheDir?.canonicalPath?.let { add(it) }
            ctx.getExternalFilesDir(null)?.canonicalPath?.let { add(it) }
            ctx.externalCacheDir?.canonicalPath?.let { add(it) }
        }
        
        // Fail-safe: If no allowed paths could be determined, prevent provider from starting
        if (allowedBasePaths.isEmpty()) {
            throw IllegalStateException("Unable to initialize allowed paths. FileProvider cannot start securely.")
        }
        
        // Detect if root path "/" is configured - reject it immediately (Mitigation Note #1 & #2)
        if (allowedBasePaths.contains("/") || allowedBasePaths.any { it == "/" }) {
            throw IllegalStateException("Root path '/' detected in FileProvider configuration. This is a critical security vulnerability.")
        }
    }

        values: ContentValues?,
    // Enhanced path validation using whitelist approach (Mitigation Note #3)
    private fun validateAndResolvePath(uri: Uri): File {
        val requestedPath = uri.path ?: throw SecurityException("Invalid URI path")
        
        // Detect path traversal attempts using ".." sequences (Defense in depth)
        if (requestedPath.contains("..")) {
            throw SecurityException("Access denied: Path traversal detected")
        }
        
        // Extract only the filename from the URI to prevent path manipulation (Mitigation Note #3)
        val fileName = requestedPath.substringAfterLast('/')
        if (fileName.isEmpty() || fileName.contains("/") || fileName.contains("\\")) {
            throw SecurityException("Access denied: Invalid filename format")
        }
        
        // Positive whitelist approach: Construct path explicitly within allowed boundaries (Mitigation Note #3)
        var validatedFile: File? = null
        for (allowedPath in allowedBasePaths) {
            val candidateFile = File(allowedPath, fileName)
            val canonicalPath = candidateFile.canonicalPath
            
            // Verify the resolved canonical path is within the allowed directory boundary
            if (canonicalPath.startsWith(allowedPath + File.separator) || canonicalPath == allowedPath) {
                if (candidateFile.exists()) {
                    validatedFile = candidateFile
                    break
                }
            }
    // Sanitize log entries to prevent log forging attacks (OWASP logging security)
    private fun sanitizeLogEntry(input: String): String {
        return input.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
            .replace("\u0000", "").take(200) // Remove null bytes and limit length
    }

    // Added caller validation to enforce authorized app access only (Mitigation Note #4)
    private fun validateCallerPermissions() {
        val callingUid = Binder.getCallingUid()
        val ctx = context ?: throw SecurityException("Context unavailable for permission check")
        val packageManager = ctx.packageManager
        
        // Get packages associated with the calling UID
        val callingPackages = packageManager.getPackagesForUid(callingUid)
        
        // Whitelist of authorized packages (configure based on your app's requirements)
        val authorizedPackages = setOf(
            ctx.packageName, // Allow same app access
            // Add other authorized package names here if needed
        )
        
        // Verify caller is authorized
        val isAuthorized = callingPackages?.any { it in authorizedPackages } == true
        if (!isAuthorized) {
            throw SecurityException("Access denied: Unauthorized calling application")
    // Validate and restrict file access modes to prevent RCE through file overwriting (Mitigation Note #5)
    private fun validateFileAccessMode(mode: String, file: File) {
        // Restrict to read-only access by default to prevent native library overwriting
        val allowedModes = setOf("r") // Only read mode allowed by default
        
        if (!allowedModes.contains(mode)) {
            throw SecurityException("Access denied: Write operations are not permitted. Only read mode 'r' is allowed.")
        }
        
        // Additional check: Ensure file is not in native library directories
        val canonicalPath = file.canonicalPath
        if (canonicalPath.contains("/lib/") || canonicalPath.contains("/lib64/") || 
            canonicalPath.endsWith(".so")) {
            throw SecurityException("Access denied: Access to native libraries is prohibited")
        }
    }
    // Override openFile with comprehensive security checks (Enhanced)
    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor? {
        // Validate URI matches expected pattern
        val matchResult = uriMatcher?.match(uri)
        if (matchResult != URI_CODE) {
            throw SecurityException("Invalid URI")
        }
        
        try {
            // Enforce caller permissions to prevent unauthorized app access (Mitigation Note #4)
            validateCallerPermissions()
            
            // Validate and resolve the file path using whitelist approach (Mitigation Note #3)
            val file = validateAndResolvePath(uri)
            
            // Check if file exists within allowed boundaries
            if (!file.exists()) {
                throw FileNotFoundException("File not found: ${sanitizeLogEntry(uri.toString())}")
            }
            
            // Validate and restrict file access mode to prevent RCE (Mitigation Note #5)
            validateFileAccessMode(mode, file)
            
            // Open file with validated mode after all security checks
            return ParcelFileDescriptor.open(file, ParcelFileDescriptor.parseMode(mode))
            
        } catch (e: SecurityException) {
            // Log security violations with sanitized entries to prevent log injection
    // Override getType with comprehensive security validation
    override fun getType(uri: Uri): String? {
        // Validate URI matches expected pattern
        val matchResult = uriMatcher?.match(uri)
        if (matchResult != URI_CODE) {
            throw SecurityException("Invalid URI")
        }
        
        try {
            // Enforce caller permissions (Mitigation Note #4)
            validateCallerPermissions()
            
            // Validate path before processing using whitelist approach
            validateAndResolvePath(uri)
            
            // Return generic mime type after validation
            return "application/octet-stream"
        } catch (e: SecurityException) {
            android.util.Log.w("InsecureshopFileProvider", "Security violation in getType: ${sanitizeLogEntry(e.message ?: "Unknown")}")
            throw e
        }
    }
