const protocolRegistry = require('../../src');

const protocol = 'fileopener';

async function deregisterScheme() {
    console.log(`De-registering protocol: "${protocol}"`);
    try {
        const isExist = await protocolRegistry.checkIfExists(protocol);
        if (!isExist) {
            console.log('Protocol is not registered. Nothing to do.');
            return;
        }
        await protocolRegistry.deRegister(protocol);
        console.log('Protocol de-registration successful!');
    } catch (e) {
        console.error('Error during de-registration:', e);
    }
}

deregisterScheme();
