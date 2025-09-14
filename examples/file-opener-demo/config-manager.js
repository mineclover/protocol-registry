const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG_DIR = path.join(os.homedir(), '.protocol-registry', 'config');
const CONFIG_FILE = path.join(CONFIG_DIR, 'fileopener.json');

function ensureConfigExists() {
    if (!fs.existsSync(CONFIG_DIR)) {
        fs.mkdirSync(CONFIG_DIR, { recursive: true });
    }
    if (!fs.existsSync(CONFIG_FILE)) {
        fs.writeFileSync(CONFIG_FILE, JSON.stringify({}, null, 2));
    }
}

function readConfig() {
    ensureConfigExists();
    const fileContent = fs.readFileSync(CONFIG_FILE, 'utf-8');
    return JSON.parse(fileContent);
}

function writeConfig(config) {
    fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function addProject(projectName, projectPath) {
    if (!projectName) {
        console.error('Error: Project name is required.');
        printUsage();
        return;
    }

    const absolutePath = projectPath
        ? path.resolve(projectPath)
        : process.cwd();

    if (!fs.existsSync(absolutePath)) {
        console.error(
            `Error: The specified path does not exist: ${absolutePath}`
        );
        return;
    }

    const config = readConfig();

    config[projectName] = absolutePath;
    writeConfig(config);
    console.log(`Success: Added/updated project "${projectName}".`);
    console.log(`  -> ${absolutePath}`);
}

function removeProject(projectName) {
    if (!projectName) {
        console.error('Error: Project name is required.');
        printUsage();
        return;
    }
    const config = readConfig();

    let removed = false;

    if (config[projectName]) {
        delete config[projectName];
        removed = true;
    }

    if (removed) {
        writeConfig(config);
        console.log(`Success: Removed project "${projectName}".`);
    } else {
        console.log(`Info: Project "${projectName}" not found in config.`);
    }
}

function listProjects() {
    const config = readConfig();

    const projects = Object.keys(config);
    if (projects.length === 0) {
        console.log('No projects configured yet.');
        return;
    }
    console.log('Configured Projects:');
    for (const project of projects) {
        console.log(`- ${project}: ${config[project]}`);
    }
}

function printUsage() {
    console.log(`
Config Manager for File Opener

Usage:
  node examples/config-manager.js <command> [args]

Commands:
  list                      - List all configured projects.
  add <name> [path]         - Add or update a project. Uses current directory if path is omitted.
  remove <name>             - Remove a project from the configuration.

Example:
  node examples/config-manager.js add my-project /path/to/your/project

URL Format:
  fileopener://projectName/path/to/file

Web Redirect Service (for browsers):
  https://fileopener-redirect.astralclover.workers.dev/projectName/path/to/file
  `);
}

const [, , command, ...args] = process.argv;

switch (command) {
    case 'list':
        listProjects();
        break;
    case 'add':
        addProject(args[0], args[1]);
        break;
    case 'remove':
        removeProject(args[0]);
        break;
    default:
        printUsage();
        break;
}
