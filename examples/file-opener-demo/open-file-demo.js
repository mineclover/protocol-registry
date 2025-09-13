const path = require('path');
const protocolRegistry = require('../../src'); // Use the local source

const protocol = 'fileopener';
// Construct the command to execute our file handler script.
// __dirname will be the 'examples' directory.
// `$_URL_` is the special placeholder that will be replaced with the actual URL.
const command = `node ${path.join(__dirname, 'file-handler.js')} "$_URL_"`;

async function registerScheme() {
    console.log(`Registering protocol: "${protocol}"`);
    console.log(`With command: "${command}"`);

    try {
        await protocolRegistry.register(protocol, command, {
            override: true,
            terminal: false
        });
        console.log('\nProtocol registration successful!');
        console.log('You can now test the protocol.');
    } catch (e) {
        console.error('\nError during protocol registration:', e);
    }
}

registerScheme();
