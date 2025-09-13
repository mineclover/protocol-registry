// This file is should not exist ideally
// still we are having this because winreg 1.2.5 has a issue that it sets shell: true
// because of which there are lot of quotes issues
// Thus we are having this until they fix it.
const spawn = require('child_process').spawn;
const path = require('path');
const { REG_TYPES } = require('winreg');
const { logSecurityEvent } = require('../utils/securityHelper');

function convertArchString(archString) {
    if (archString == 'x64') {
        return '64';
    } else if (archString == 'x86') {
        return '32';
    } else {
        throw new Error(
            'illegal architecture: ' + archString + ' (use x86 or x64)'
        );
    }
}

function getRegExePath() {
    if (process.platform === 'win32') {
        return path.join(process.env.windir, 'system32', 'reg.exe');
    } else {
        return 'REG';
    }
}

function trimQuotesIfPresent(value) {
    if (typeof value !== 'string') {
        throw new Error('Value must be a string');
    }

    if (
        value.length >= 2 &&
        ((value[0] === '"' && value[value.length - 1] === '"') ||
            // eslint-disable-next-line quotes
            (value[0] === "'" && value[value.length - 1] === "'"))
    ) {
        return value.slice(1, value.length - 1);
    }

    return value;
}

exports.processRegistryPath = (registryPath) => {
    return trimQuotesIfPresent(registryPath);
};

exports.setRegistry = (registry, options) => {
    return new Promise((resolve, reject) => {
        const { name, type, value } = options;

        // Security: Validate inputs
        if (!registry || !registry.path) {
            throw new Error('Registry path is required');
        }

        if (REG_TYPES.indexOf(type) == -1) {
            throw Error('illegal type specified.');
        }

        // Security: Log registry modification attempt
        logSecurityEvent('REGISTRY_MODIFICATION', {
            path: registry.path,
            name: name,
            type: type,
            hasValue: !!value
        });

        let args = ['ADD', trimQuotesIfPresent(registry.path)];
        if (name == '') args.push('/ve');
        else args = args.concat(['/v', name]);

        args = args.concat(['/t', type, '/d', value, '/f']);

        if (registry.arch) {
            args.push('/reg:' + convertArchString(registry.arch));
        }

        // Security: Enhanced spawn options
        const proc = spawn(getRegExePath(), args, {
            cwd: undefined,
            env: { ...process.env, PATH: process.env.PATH }, // Only pass necessary env vars
            windowsHide: true,
            stdio: ['ignore', 'pipe', 'pipe'],
            timeout: 30000, // 30 second timeout
            shell: false // Explicitly disable shell
        });
        let error = null; // null means no error previously reported.

        const output = { stdout: '', stderr: '' };

        proc.stdout.on('data', function (data) {
            output['stdout'] += data.toString();
        });
        proc.stderr.on('data', function (data) {
            output['stderr'] += data.toString();
        });

        proc.on('close', function (code) {
            if (error) {
                return;
            } else if (code !== 0) {
                logSecurityEvent('REGISTRY_MODIFICATION_FAILED', {
                    path: registry.path,
                    exitCode: code,
                    stdout: output.stdout,
                    stderr: output.stderr
                });
                reject(
                    new Error(
                        'Registry failed because : ' +
                            output.stdout +
                            '\n\n' +
                            output.stderr
                    )
                );
            } else {
                logSecurityEvent('REGISTRY_MODIFICATION_SUCCESS', {
                    path: registry.path,
                    name: name
                });
                resolve();
            }
        });

        proc.on('error', function (err) {
            error = err;
            logSecurityEvent('REGISTRY_MODIFICATION_ERROR', {
                path: registry.path,
                error: err.message
            });
            reject(err);
        });

        return this;
    });
};
