const { exec } = require('child_process');
const { promisify } = require('util');

const execAsync = promisify(exec);

/**
 * Test helper for scheme-to-scheme routing
 * This simulates a scenario where one protocol redirects to another
 */

async function createSchemeRouter(fromScheme, toScheme, targetUrl) {
    // Create a simple Node.js script that redirects from one scheme to another
    const routerScript = `
const { exec } = require('child_process');

// Get the URL from command line argument
const inputUrl = process.argv[2];
console.log('[SCHEME-ROUTER] Received:', inputUrl);

// Parse the input URL and extract the path/query
const url = new URL(inputUrl);
const pathAndQuery = url.pathname + url.search;

// Create the target URL with the new scheme
const targetUrl = '${toScheme}://' + pathAndQuery;
console.log('[SCHEME-ROUTER] Redirecting to:', targetUrl);

// On macOS, use 'open' command to trigger the target scheme
if (process.platform === 'darwin') {
    exec(\`open "\${targetUrl}"\`, (error, stdout, stderr) => {
        if (error) {
            console.error('[SCHEME-ROUTER] Error:', error);
            process.exit(1);
        }
        console.log('[SCHEME-ROUTER] Successfully redirected');
        process.exit(0);
    });
} else {
    console.log('[SCHEME-ROUTER] Would redirect to:', targetUrl);
    process.exit(0);
}
    `.trim();

    return routerScript;
}

async function createTargetHandler(scheme, message) {
    // Create a script that handles the target scheme
    const handlerScript = `
const inputUrl = process.argv[2];
console.log('[TARGET-HANDLER] ${message}');
console.log('[TARGET-HANDLER] Received URL:', inputUrl);

// Write to a test file to verify the redirection worked
const fs = require('fs');
const path = require('path');
const testFile = path.join(__dirname, 'scheme-routing-test.log');

const logEntry = {
    timestamp: new Date().toISOString(),
    scheme: '${scheme}',
    url: inputUrl,
    message: '${message}'
};

fs.appendFileSync(testFile, JSON.stringify(logEntry) + '\\n');
console.log('[TARGET-HANDLER] Logged to:', testFile);
    `.trim();

    return handlerScript;
}

module.exports = {
    createSchemeRouter,
    createTargetHandler
};
