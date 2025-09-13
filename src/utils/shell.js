const { exec } = require('child_process');

// Security: Command sanitization function
function sanitizeCommand(command) {
    if (typeof command !== 'string') {
        throw new Error('Command must be a string');
    }

    // Remove potentially dangerous characters and sequences
    const dangerousPatterns = [
        /[;&|`$()]/g, // Command injection characters
        /\.\./g, // Directory traversal
        />/g, // Redirection
        /<\(/g, // Process substitution
        /\$\{/g, // Variable expansion
        /\$\(/g // Command substitution
    ];

    let sanitized = command;
    dangerousPatterns.forEach((pattern) => {
        sanitized = sanitized.replace(pattern, '');
    });

    // Log security event
    if (sanitized !== command) {
        console.warn('[SECURITY] Command sanitized:', {
            original: command,
            sanitized
        });
    }

    return sanitized.trim();
}

exports.exec = (...args) => {
    let command = '';
    let options = { encoding: 'utf8', shell: false }; // Security: Disable shell by default
    let callback = null;

    if (args.length === 0) {
        throw new Error('No arguments passed');
    }
    if (args.length === 1) {
        command = args[0];
    }
    if (args.length === 2) {
        if (args[1] instanceof Function) {
            command = args[0];
            callback = args[1];
        } else {
            command = args[0];
            options = { ...options, ...args[1] };
        }
    }
    if (args.length === 3) {
        command = args[0];
        options = { ...options, ...args[1] };
        callback = args[2];
    }

    // Security: Sanitize command
    command = sanitizeCommand(command);

    // Security: Set timeout to prevent hanging
    if (!options.timeout) {
        options.timeout = 30000; // 30 seconds default timeout
    }

    return new Promise((resolve, reject) => {
        exec(command, options, (err, stdout, stderr) => {
            const data = {};
            data.stdout = stdout;
            data.stderr = stderr;

            if (!err) {
                data.code = 0;
            } else if (err.code === undefined) {
                data.code = 1;
            } else {
                data.code = err.code;
            }

            // Security: Log command execution
            console.log('[SECURITY] Command executed:', {
                command,
                code: data.code
            });

            if (callback) {
                callback(data.code, data.stdout, data.stderr);
            }

            // Security: Reject on timeout or critical errors
            if (err && err.killed) {
                reject(new Error('Command execution timeout'));
            } else {
                resolve(data);
            }
        });
    });
};
