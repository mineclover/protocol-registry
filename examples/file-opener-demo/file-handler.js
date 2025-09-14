const fs = require('fs');
const path = require('path');
const os = require('os');
const { URL } = require('url');

const CONFIG_FILE = path.join(
    os.homedir(),
    '.protocol-registry',
    'config',
    'fileopener.json'
);

function getConfig() {
    if (!fs.existsSync(CONFIG_FILE)) {
        // If you get this error, run the config-manager.js script to add a project.
        throw new Error(`Config file not found at: ${CONFIG_FILE}`);
    }
    const fileContent = fs.readFileSync(CONFIG_FILE, 'utf-8');
    return JSON.parse(fileContent);
}

function openFile(absolutePath) {
    if (!fs.existsSync(absolutePath)) {
        throw new Error(`File does not exist at path: ${absolutePath}`);
    }

    // On success, print the absolute path to stdout. The AppleScript handler will read this.
    console.log(absolutePath);
}

function handleUrl(urlString) {
    if (!urlString) {
        throw new Error('No URL provided.');
    }

    // Decode URL to handle encoded characters
    const decodedUrlString = decodeURIComponent(urlString);

    // Debug: Log the decoded URL
    fs.appendFileSync(
        path.join(os.homedir(), '.protocol-registry', 'log.txt'),
        `${new Date().toISOString()}: Decoded URL: ${decodedUrlString}\n`
    );

    const url = new URL(decodedUrlString);

    // Parse URL to support both formats:
    // 1. Legacy format: fileopener://projectName?path=/src/file.js
    // 2. New format: fileopener://projectName/src/file.js

    let projectName = url.hostname;
    let relativePath = null;

    // Handle special case for config
    if (projectName === 'config' && !url.pathname.replace(/^\/+/, '')) {
        openFile(CONFIG_FILE);
        return;
    }

    // Check if we're using the new format (path in pathname)
    if (url.pathname && url.pathname !== '/') {
        // New format: fileopener://projectName/path/to/file
        relativePath = url.pathname.substring(1); // Remove leading slash
    } else {
        // Legacy format: check for path in query parameters
        relativePath = url.searchParams.get('path');
    }

    // Fallback for systems that parse differently
    if (!projectName && url.pathname) {
        // On some systems, "fileopener://config" might be parsed with pathname="config"
        // and an empty hostname. We remove leading slashes if they exist.
        const pathParts = url.pathname.replace(/^\/+/g, '').split('/');
        projectName = pathParts[0];
        if (pathParts.length > 1) {
            relativePath = pathParts.slice(1).join('/');
        }
    }

    if (!projectName) {
        throw new Error('Project name not found in URL.');
    }

    if (!relativePath) {
        throw new Error('File path not found in URL. Use format: fileopener://projectName/path/to/file');
    }

    const config = getConfig();

    const projectBasePath = config[projectName];

    if (!projectBasePath) {
        throw new Error(
            `Project "${projectName}" is not defined in the config file.`
        );
    }

    const absolutePath = path.join(projectBasePath, relativePath);

    // Security Check: Ensure the resolved path is within the project's base path.
    // This prevents directory traversal attacks (e.g., path=../../../../../etc/passwd)
    const resolvedPath = path.resolve(absolutePath);
    const resolvedBasePath = path.resolve(projectBasePath);

    if (!resolvedPath.startsWith(resolvedBasePath)) {
        throw new Error(
            'Security violation: Attempted to access a file outside the project directory.'
        );
    }

    openFile(resolvedPath);
}

try {
    const urlString = process.argv[2];
    // Debug: Log the received URL
    fs.appendFileSync(
        path.join(os.homedir(), '.protocol-registry', 'log.txt'),
        `${new Date().toISOString()}: Received URL: ${urlString}\n`
    );
    handleUrl(urlString);
} catch (e) {
    // You can write this error to a log file for debugging
    console.error('An error occurred:', e.message);
    fs.appendFileSync(
        path.join(os.homedir(), '.protocol-registry', 'log.txt'),
        `${new Date().toISOString()}: Error: ${e.message}\n${new Date().toISOString()}: ${e.stack}\n`
    );
    throw new Error(`Process exit with code 1: ${e.message}`);
}
