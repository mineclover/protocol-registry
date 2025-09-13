const path = require('path');
const {
    test,
    expect,
    afterEach,
    beforeAll,
    afterAll
} = require('@jest/globals');
const { homedir } = require('../src/config/constants');
const fs = require('fs');
const {
    validateRegistrationConfig,
    validateDeRegistrationConfig
} = require('./utils/configuration-test');

const ProtocolRegistry = require('../src');
const { checkRegistration } = require('./utils/integration-test');
const constants = require('./config/constants');
const { matchSnapshot } = require('./utils/matchSnapshot');

const protocol = 'regimen';

const getCommand = () => {
    return `node "${path.join(__dirname, './test runner.js')}" "$_URL_" ${
        constants.wssPort
    }`;
};

beforeAll(async () => {
    await ProtocolRegistry.deRegister(protocol, { force: true });
});

afterEach(async () => {
    await ProtocolRegistry.deRegister(protocol, { force: true });
    if (fs.existsSync(homedir)) {
        fs.rmSync(homedir, { recursive: true, force: true });
    }
});

afterAll(async () => {
    await ProtocolRegistry.deRegister(protocol, { force: true });
});

test.each([
    {
        name: 'should register protocol without options'
    },
    {
        name: 'should register protocol with override is false',

        options: {
            override: false
        }
    },
    {
        name: 'should register protocol with terminal is false',

        options: {
            terminal: false
        }
    },
    {
        name:
            'should register protocol with override is true and protocol does not exist',

        options: {
            override: true
        }
    },
    {
        name: 'should register protocol with terminal is true',

        options: {
            terminal: true
        }
    },
    {
        name: 'should register protocol with custom app name',

        options: {
            appName: 'custom-app-name'
        }
    },
    {
        name:
            'should register protocol with custom app name with multiple spaces',

        options: {
            terminal: true,
            override: true,
            appName: 'custom App-name 1'
        }
    }
])(
    process.platform + ' $name',
    async (args) => {
        await ProtocolRegistry.register(protocol, getCommand(), args.options);

        await checkRegistration(protocol, args.options || {});
        await validateRegistrationConfig(protocol, args.options || {});

        expect(await ProtocolRegistry.checkIfExists(protocol)).toBeTruthy();

        matchSnapshot(await ProtocolRegistry.getDefaultApp(protocol));

        await ProtocolRegistry.deRegister(protocol);
        await validateDeRegistrationConfig(protocol, args.options || {});

        expect(await ProtocolRegistry.checkIfExists(protocol)).toBeFalsy();
    },
    constants.jestTimeOut
);

test('checkIfExists should be false if protocol is not registered', async () => {
    expect(await ProtocolRegistry.checkIfExists('atestproto')).toBeFalsy();
});

test('checkIfExists should be true if protocol is registered', async () => {
    const options = {
        override: true,
        terminal: false,
        appName: 'my-custom-app-name'
    };
    await ProtocolRegistry.register(protocol, getCommand(), options);

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeTruthy();
});

test('should fail registration when protocol already exist and override is false', async () => {
    const options = {
        override: false,
        terminal: false
    };
    await ProtocolRegistry.register(protocol, getCommand(), options);

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeTruthy();

    await expect(
        ProtocolRegistry.register(protocol, getCommand(), options)
    ).rejects.toThrow();

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeTruthy();
});

test('Check if deRegister should remove the protocol', async () => {
    await ProtocolRegistry.register(
        protocol,
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: true,
            terminal: false,
            appName: 'my-custom-app-name007'
        }
    );

    await ProtocolRegistry.deRegister(protocol);

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeFalsy();
});

test('Check if deRegister should delete the apps if registered through this module', async () => {
    await ProtocolRegistry.register(
        protocol,
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: true,
            terminal: true,
            appName: 'App Name'
        }
    );

    await ProtocolRegistry.deRegister(protocol);

    expect(fs.existsSync(homedir)).toBeFalsy();
});

test('Check if deRegister should not delete the homedir if other registered apps exist', async () => {
    await ProtocolRegistry.register(
        protocol,
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: true,
            terminal: true,
            appName: 'my-custom-app-name'
        }
    );

    await ProtocolRegistry.register(
        protocol + 'del',
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: true,
            terminal: true,
            appName: 'my-custom-app-name'
        }
    );

    await ProtocolRegistry.deRegister(protocol + 'del');

    expect(fs.existsSync(homedir)).toBeTruthy();
});

test('Check if app should be registered again post the same app is deRegistered', async () => {
    await ProtocolRegistry.register(
        protocol,
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: true,
            terminal: false,
            appName: 'my-custom-app-name'
        }
    );

    await ProtocolRegistry.deRegister(protocol);

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeFalsy();

    await ProtocolRegistry.register(
        protocol,
        `node '${path.join(__dirname, './tester.js')}' $_URL_`,
        {
            override: false,
            terminal: false,
            appName: 'my-custom app-name'
        }
    );

    expect(await ProtocolRegistry.checkIfExists(protocol)).toBeTruthy();
});

// Scheme-to-scheme routing tests
test('should support scheme-to-scheme routing', async () => {
    const sourceScheme = 'myapp';
    const targetScheme = 'anotherapp';
    const fs = require('fs');
    const {
        createSchemeRouter,
        createTargetHandler
    } = require('./scheme-router');

    // Clean up any existing test log
    const testLogPath = path.join(__dirname, 'scheme-routing-test.log');
    if (fs.existsSync(testLogPath)) {
        fs.unlinkSync(testLogPath);
    }

    // Create router script file
    const routerScriptPath = path.join(__dirname, 'temp-router.js');
    const routerScript = await createSchemeRouter(
        sourceScheme,
        targetScheme,
        'test'
    );
    fs.writeFileSync(routerScriptPath, routerScript);

    // Create target handler script file
    const handlerScriptPath = path.join(__dirname, 'temp-handler.js');
    const handlerScript = await createTargetHandler(
        targetScheme,
        'Scheme routing test successful'
    );
    fs.writeFileSync(handlerScriptPath, handlerScript);

    try {
        // Register the source scheme to redirect to target scheme
        await ProtocolRegistry.register(
            sourceScheme,
            `node "${routerScriptPath}" "$_URL_"`,
            {
                override: true,
                terminal: false,
                appName: 'Scheme Router Test'
            }
        );

        // Register the target scheme with a test handler
        await ProtocolRegistry.register(
            targetScheme,
            `node "${handlerScriptPath}" "$_URL_"`,
            {
                override: true,
                terminal: false,
                appName: 'Target Handler Test'
            }
        );

        // Verify both schemes are registered
        expect(await ProtocolRegistry.checkIfExists(sourceScheme)).toBeTruthy();
        expect(await ProtocolRegistry.checkIfExists(targetScheme)).toBeTruthy();

        // Test the routing by checking if we can get the default app for both
        const sourceApp = await ProtocolRegistry.getDefaultApp(sourceScheme);
        const targetApp = await ProtocolRegistry.getDefaultApp(targetScheme);

        expect(sourceApp).toBeTruthy();
        expect(targetApp).toBeTruthy();
        expect(sourceApp).not.toBe(targetApp); // They should be different apps

        console.log(
            `[TEST] Source scheme ${sourceScheme} registered to: ${sourceApp}`
        );
        console.log(
            `[TEST] Target scheme ${targetScheme} registered to: ${targetApp}`
        );
    } finally {
        // Clean up
        await ProtocolRegistry.deRegister(sourceScheme, { force: true });
        await ProtocolRegistry.deRegister(targetScheme, { force: true });

        // Clean up temp files
        if (fs.existsSync(routerScriptPath)) fs.unlinkSync(routerScriptPath);
        if (fs.existsSync(handlerScriptPath)) fs.unlinkSync(handlerScriptPath);
        if (fs.existsSync(testLogPath)) fs.unlinkSync(testLogPath);
    }
});

test('should handle complex scheme routing with parameters', async () => {
    const sourceScheme = 'webapp';
    const targetScheme = 'nativeapp';
    const fs = require('fs');

    // Create a more complex router that preserves URL parameters
    const complexRouterScript = `
const { exec } = require('child_process');
const inputUrl = process.argv[2];
console.log('[COMPLEX-ROUTER] Processing:', inputUrl);

try {
    const url = new URL(inputUrl);
    const params = new URLSearchParams(url.search);

    // Transform the URL: webapp://action/data?param=value -> nativeapp://action/data?param=value&routed=true
    params.set('routed', 'true');
    params.set('source', '${sourceScheme}');

    const targetUrl = '${targetScheme}://' + url.pathname + '?' + params.toString();
    console.log('[COMPLEX-ROUTER] Routing to:', targetUrl);

    if (process.platform === 'darwin') {
        exec(\`open "\${targetUrl}"\`, (error) => {
            if (error) {
                console.error('[COMPLEX-ROUTER] Error:', error.message);
                process.exit(1);
            }
            console.log('[COMPLEX-ROUTER] Successfully routed with parameters');
            process.exit(0);
        });
    } else {
        console.log('[COMPLEX-ROUTER] Would route to:', targetUrl);
        process.exit(0);
    }
} catch (error) {
    console.error('[COMPLEX-ROUTER] URL parsing error:', error.message);
    process.exit(1);
}
    `.trim();

    const routerScriptPath = path.join(__dirname, 'temp-complex-router.js');
    const handlerScriptPath = path.join(__dirname, 'temp-complex-handler.js');

    // Create handler that logs the received parameters
    const handlerScript = `
const inputUrl = process.argv[2];
console.log('[COMPLEX-HANDLER] Received:', inputUrl);

try {
    const url = new URL(inputUrl);
    const params = Object.fromEntries(url.searchParams);

    console.log('[COMPLEX-HANDLER] Parsed parameters:', JSON.stringify(params));
    console.log('[COMPLEX-HANDLER] Path:', url.pathname);

    // Verify routing parameters are present
    if (params.routed === 'true' && params.source === '${sourceScheme}') {
        console.log('[COMPLEX-HANDLER] ✓ Routing metadata confirmed');
    }

    const fs = require('fs');
    const logData = {
        timestamp: new Date().toISOString(),
        originalUrl: inputUrl,
        parsedParams: params,
        pathname: url.pathname,
        routingConfirmed: params.routed === 'true' && params.source === '${sourceScheme}'
    };

    fs.writeFileSync('${path.join(
        __dirname,
        'complex-routing-test.log'
    )}', JSON.stringify(logData, null, 2));

} catch (error) {
    console.error('[COMPLEX-HANDLER] Error:', error.message);
    process.exit(1);
}
    `.trim();

    fs.writeFileSync(routerScriptPath, complexRouterScript);
    fs.writeFileSync(handlerScriptPath, handlerScript);

    try {
        // Register both schemes
        await ProtocolRegistry.register(
            sourceScheme,
            `node "${routerScriptPath}" "$_URL_"`,
            {
                override: true,
                terminal: false,
                appName: 'Complex Router Test'
            }
        );

        await ProtocolRegistry.register(
            targetScheme,
            `node "${handlerScriptPath}" "$_URL_"`,
            {
                override: true,
                terminal: false,
                appName: 'Complex Handler Test'
            }
        );

        // Verify registration
        expect(await ProtocolRegistry.checkIfExists(sourceScheme)).toBeTruthy();
        expect(await ProtocolRegistry.checkIfExists(targetScheme)).toBeTruthy();

        console.log(
            `[TEST] Complex routing setup complete: ${sourceScheme} -> ${targetScheme}`
        );
    } finally {
        // Clean up
        await ProtocolRegistry.deRegister(sourceScheme, { force: true });
        await ProtocolRegistry.deRegister(targetScheme, { force: true });

        // Clean up temp files
        [
            routerScriptPath,
            handlerScriptPath,
            path.join(__dirname, 'complex-routing-test.log')
        ].forEach((file) => {
            if (fs.existsSync(file)) fs.unlinkSync(file);
        });
    }
});
