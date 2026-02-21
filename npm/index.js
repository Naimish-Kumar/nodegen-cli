#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const os = require('os');

function getBinaryName() {
    const platform = os.platform();
    const arch = os.arch();

    // Map platform and arch to your pre-compiled binaries
    if (platform === 'win32') {
        return 'node-project-gen-win.exe';
    } else if (platform === 'darwin') {
        return 'node-project-gen-macos';
    } else if (platform === 'linux') {
        if (arch === 'x64') return 'node-project-gen-linux';
        if (arch === 'arm64') return 'node-project-gen-linux-arm64';
    }

    throw new Error(`Unsupported platform: ${platform} ${arch}`);
}

const binaryName = getBinaryName();
const binaryPath = path.join(__dirname, 'bin', binaryName);

// Forward all arguments to the Rust binary
const child = spawn(binaryPath, process.argv.slice(2), {
    stdio: 'inherit'
});

child.on('error', (err) => {
    console.error(`Failed to start NodeGen: ${err.message}`);
    process.exit(1);
});

child.on('exit', (code) => {
    process.exit(code);
});
