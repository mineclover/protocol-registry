const path = require('path');
const os = require('os');

/**
 * Security helper utilities for path validation and sanitization
 */

// Security: Safe path validation
function validatePath(filePath) {
    if (typeof filePath !== 'string') {
        throw new Error('Path must be a string');
    }

    // Normalize the path to prevent directory traversal
    const normalizedPath = path.normalize(filePath);

    // Check for directory traversal attempts
    if (normalizedPath.includes('..')) {
        throw new Error('Path traversal detected');
    }

    // Ensure path doesn't start with system directories
    const dangerousRoots = ['/etc', '/bin', '/sbin', '/boot', '/sys', '/proc'];
    const absolutePath = path.resolve(normalizedPath);

    for (const dangerousRoot of dangerousRoots) {
        if (absolutePath.startsWith(dangerousRoot)) {
            throw new Error(
                `Access to system directory denied: ${dangerousRoot}`
            );
        }
    }

    return normalizedPath;
}

// Security: Create safe directory within user's home
function createSafeUserPath(subPath) {
    const homeDir = os.homedir();
    const safePath = path.join(
        homeDir,
        '.protocol-registry',
        validatePath(subPath)
    );

    // Ensure the path is within user's protocol-registry directory
    const protocolRegistryDir = path.join(homeDir, '.protocol-registry');
    if (!safePath.startsWith(protocolRegistryDir)) {
        throw new Error('Path must be within protocol-registry directory');
    }

    return safePath;
}

// Security: Validate protocol name more strictly
function validateProtocolName(protocol) {
    if (typeof protocol !== 'string') {
        throw new Error('Protocol must be a string');
    }

    // More strict validation: only alphanumeric characters, length limits
    if (!/^[a-zA-Z][a-zA-Z0-9]{0,31}$/.test(protocol)) {
        throw new Error(
            'Invalid protocol name. Must start with letter, contain only alphanumeric characters, max 32 chars'
        );
    }

    // Prevent reserved protocol names
    const reservedProtocols = [
        'http',
        'https',
        'ftp',
        'file',
        'mailto',
        'tel',
        'sms'
    ];
    if (reservedProtocols.includes(protocol.toLowerCase())) {
        throw new Error(`Cannot use reserved protocol name: ${protocol}`);
    }

    return protocol;
}

// Security: Validate command path
function validateCommandPath(command) {
    if (typeof command !== 'string') {
        throw new Error('Command must be a string');
    }

    // Remove null bytes and control characters (escape sequences for ESLint)
    // eslint-disable-next-line no-control-regex
    const sanitized = command.replace(/[\x00-\x08\x0E-\x1F\x7F]/g, '');

    // Check for dangerous patterns
    const dangerousPatterns = [
        /\b(rm\s+-rf|del\s+\/[sq]|format\s+c:)/i, // Dangerous system commands
        /\b(nc\s+|netcat\s+|telnet\s+)/i, // Network tools
        /\b(curl\s+|wget\s+|powershell\s+)/i, // Download tools
        /\b(eval\s+|exec\s+)/i // Code execution
    ];

    for (const pattern of dangerousPatterns) {
        if (pattern.test(sanitized)) {
            throw new Error('Potentially dangerous command detected');
        }
    }

    return sanitized;
}

// Security: Log security events
function logSecurityEvent(event, details) {
    const timestamp = new Date().toISOString();
    const logEntry = {
        timestamp,
        event,
        details,
        pid: process.pid,
        platform: process.platform
    };

    console.log('[SECURITY EVENT]', JSON.stringify(logEntry));
}

module.exports = {
    validatePath,
    createSafeUserPath,
    validateProtocolName,
    validateCommandPath,
    logSecurityEvent
};
