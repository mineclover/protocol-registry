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

    const url = new URL(urlString);
    // Browsers might not pass hostname for simple URLs like "scheme:host".
    // Handle both url.hostname and url.pathname for robustness.
    let projectName = url.hostname;
    if (!projectName && url.pathname) {
        // On some systems, "fileopener://config" might be parsed with pathname="config"
        // and an empty hostname. We remove leading slashes if they exist.
        projectName = url.pathname.replace(/^\/+/g, '');
    }

    if (projectName === 'config') {
        // Special case: open the configuration file itself.
        openFile(CONFIG_FILE);
        return;
    }

    const relativePath = url.searchParams.get('path');

    if (!projectName) {
        throw new Error('Project name not found in URL hostname.');
    }
    if (!relativePath) {
        throw new Error('"path" query parameter not found in the URL.');
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
    handleUrl(urlString);
} catch (e) {
    // You can write this error to a log file for debugging
    console.error('An error occurred:', e.message);
    fs.appendFileSync(
        path.join(os.homedir(), '.protocol-registry', 'log.txt'),
        `${new Date().toISOString()}: ${e.stack}\n`
    );
    throw new Error(`Process exit with code 1: ${e.message}`);
}
