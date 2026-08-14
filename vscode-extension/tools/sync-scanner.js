#!/usr/bin/env node
'use strict';
//
// Copy the scanner into resources/ so it ships inside the VSIX.
//
// The extension needs its own copy — a Marketplace install has no repository
// checkout to read scripts/ from — but a second committed copy would drift
// from the original. So the copy is generated at package time from the single
// source of truth in scripts/, and resources/ is gitignored.
//
// Run automatically by the `prevsix` and `prevsix:publish` npm hooks.

const fs = require('fs');
const path = require('path');

const SOURCE = path.join(__dirname, '..', '..', 'scripts', 'cfml_sast_simple.py');
const TARGET_DIR = path.join(__dirname, '..', 'resources');
const TARGET = path.join(TARGET_DIR, 'cfml_sast_simple.py');

if (!fs.existsSync(SOURCE)) {
    console.error(`sync-scanner: source not found at ${SOURCE}`);
    console.error('sync-scanner: run this from a full CF-SAST checkout, not a standalone extension copy.');
    process.exit(1);
}

fs.mkdirSync(TARGET_DIR, { recursive: true });
fs.copyFileSync(SOURCE, TARGET);

const bytes = fs.statSync(TARGET).size;
console.log(`sync-scanner: copied cfml_sast_simple.py -> resources/ (${bytes} bytes)`);
