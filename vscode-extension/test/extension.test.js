'use strict';
//
// Unit tests for the extension's pure helpers.
//
// extension.js requires the `vscode` module, which only exists inside the
// editor host, so it is stubbed here. The helpers under test never touch it.

const Module = require('module');
const originalLoad = Module._load;
Module._load = function (request, ...rest) {
    if (request === 'vscode') {
        return {};
    }
    return originalLoad.call(this, request, ...rest);
};

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const {
    isInside, parseFindings, sanitizeFindings, resolveFindingPath, generateResultsHtml
} = require('../extension.js');

test('isInside accepts a real descendant', () => {
    assert.strictEqual(isInside('/work', '/work/src/a.cfm'), true);
    assert.strictEqual(isInside('/work', '/work'), true);
});

test('isInside rejects a sibling sharing a name prefix', () => {
    // The startsWith() check this replaced accepted this path.
    assert.strictEqual(isInside('/work', '/work-evil/a.cfm'), false);
});

test('isInside rejects traversal out of the workspace', () => {
    assert.strictEqual(isInside('/work', path.join('/work', '..', 'etc', 'passwd')), false);
});

test('parseFindings reads the plain JSON array format', () => {
    const findings = parseFindings(JSON.stringify([
        { file: 'a.cfm', line: 3, rule_id: 'CF-SQLI-001', severity: 'HIGH', description: 'x' }
    ]));
    assert.strictEqual(findings.length, 1);
    assert.strictEqual(findings[0].rule_id, 'CF-SQLI-001');
});

test('parseFindings reads SARIF, which the old parser rejected outright', () => {
    const sarif = {
        version: '2.1.0',
        runs: [{
            tool: { driver: { name: 'CFML SAST Scanner', rules: [] } },
            results: [{
                ruleId: 'CF-XSS-001',
                level: 'warning',
                message: { text: 'Potential XSS' },
                locations: [{
                    physicalLocation: {
                        artifactLocation: { uri: 'src/a.cfm' },
                        region: { startLine: 12 }
                    }
                }]
            }]
        }]
    };
    const findings = parseFindings(JSON.stringify(sarif));
    assert.deepStrictEqual(findings, [{
        file: 'src/a.cfm',
        line: 12,
        rule_id: 'CF-XSS-001',
        severity: 'MEDIUM',
        description: 'Potential XSS'
    }]);
});

test('parseFindings maps every SARIF level to a severity', () => {
    const build = (level) => JSON.stringify({
        runs: [{ results: [{ ruleId: 'R', level, message: { text: '' }, locations: [] }] }]
    });
    assert.strictEqual(parseFindings(build('error'))[0].severity, 'HIGH');
    assert.strictEqual(parseFindings(build('warning'))[0].severity, 'MEDIUM');
    assert.strictEqual(parseFindings(build('note'))[0].severity, 'LOW');
});

test('parseFindings treats empty output as no findings', () => {
    assert.deepStrictEqual(parseFindings(''), []);
    assert.deepStrictEqual(parseFindings('   \n'), []);
    assert.deepStrictEqual(parseFindings('[]'), []);
});

test('parseFindings rejects unrecognised output rather than guessing', () => {
    assert.throws(() => parseFindings('{"unexpected": true}'), /Unrecognised/);
    assert.throws(() => parseFindings('not json'));
});

test('sanitizeFindings clamps hostile values', () => {
    const [f] = sanitizeFindings([{
        file: 'x'.repeat(900),
        line: -5,
        rule_id: 'y'.repeat(80),
        severity: 'CATASTROPHIC',
        description: 'z'.repeat(2000)
    }]);
    assert.strictEqual(f.file.length, 500);
    assert.strictEqual(f.line, 1);
    assert.strictEqual(f.rule_id.length, 50);
    assert.strictEqual(f.severity, 'UNKNOWN');
    assert.strictEqual(f.description.length, 1000);
});

test('sanitizeFindings drops non-objects', () => {
    assert.deepStrictEqual(sanitizeFindings([null, 'x', 42]), []);
});

// --- Clicking a finding to open it -------------------------------------

test('resolveFindingPath resolves a scanner-relative path against the workspace', () => {
    const resolved = resolveFindingPath('/work', 'src/login.cfm');
    assert.strictEqual(resolved, path.resolve('/work/src/login.cfm'));
});

test('resolveFindingPath accepts an absolute path inside the workspace', () => {
    const abs = path.resolve('/work/src/login.cfm');
    assert.strictEqual(resolveFindingPath('/work', abs), abs);
});

test('resolveFindingPath refuses paths escaping the workspace', () => {
    assert.strictEqual(resolveFindingPath('/work', '../etc/passwd'), null);
    assert.strictEqual(resolveFindingPath('/work', path.resolve('/etc/passwd')), null);
});

test('resolveFindingPath refuses empty or non-string input', () => {
    assert.strictEqual(resolveFindingPath('/work', ''), null);
    assert.strictEqual(resolveFindingPath('/work', null), null);
    assert.strictEqual(resolveFindingPath('/work', 42), null);
});

test('every rendered card carries the index the click handler sends back', () => {
    const findings = [
        { file: 'a.cfm', line: 3, rule_id: 'CF-SQLI-001', severity: 'HIGH', description: 'x' },
        { file: 'b.cfm', line: 9, rule_id: 'CF-XSS-001', severity: 'MEDIUM', description: 'y' }
    ];
    const html = generateResultsHtml(findings);
    assert.match(html, /data-index="0"/);
    assert.match(html, /data-index="1"/);
    // Keyboard reachable, and announced as actionable.
    assert.match(html, /role="button"/);
    assert.match(html, /tabindex="0"/);
});

test('cards show the full relative path, not just the basename', () => {
    const html = generateResultsHtml([
        { file: 'src/nested/login.cfm', line: 3, rule_id: 'R', severity: 'HIGH', description: 'x' }
    ]);
    assert.match(html, /src\/nested\/login\.cfm/);
});

test('the click script is admitted by the page CSP nonce', () => {
    const html = generateResultsHtml([
        { file: 'a.cfm', line: 1, rule_id: 'R', severity: 'HIGH', description: 'x' }
    ]);
    const cspNonce = html.match(/script-src 'nonce-([^']+)'/);
    const tagNonce = html.match(/<script nonce="([^"]+)"/);
    assert.ok(cspNonce, 'CSP should declare a script nonce');
    assert.ok(tagNonce, 'the inline script should carry a nonce');
    assert.strictEqual(cspNonce[1], tagNonce[1], 'nonces must match or the script is blocked');
});

test('nonces differ between renders', () => {
    const one = generateResultsHtml([{ file: 'a.cfm', line: 1, rule_id: 'R', severity: 'HIGH', description: '' }]);
    const two = generateResultsHtml([{ file: 'a.cfm', line: 1, rule_id: 'R', severity: 'HIGH', description: '' }]);
    const nonceOf = (h) => h.match(/<script nonce="([^"]+)"/)[1];
    assert.notStrictEqual(nonceOf(one), nonceOf(two));
});

test('finding text is HTML-escaped in every field it reaches', () => {
    const html = generateResultsHtml([{
        file: '<img src=x onerror=alert(1)>.cfm',
        line: 1,
        rule_id: '"><script>alert(1)</script>',
        severity: 'HIGH',
        description: "<b>bold</b> & 'quoted'"
    }]);
    assert.ok(!html.includes('<img src=x'), 'file name was not escaped');
    assert.ok(!html.includes('<script>alert(1)</script>'), 'rule id was not escaped');
    assert.ok(!html.includes('<b>bold</b>'), 'description was not escaped');
    assert.match(html, /&lt;img/);
});

test('the card list is capped and says so', () => {
    const many = Array.from({ length: 600 }, (_, i) => ({
        file: `f${i}.cfm`, line: 1, rule_id: 'R', severity: 'HIGH', description: 'x'
    }));
    const html = generateResultsHtml(many);
    const cardCount = (html.match(/data-index="/g) || []).length;
    assert.strictEqual(cardCount, 500);
    assert.match(html, /Showing the first 500 of 600 findings/);
});

test('no truncation note when everything fits', () => {
    const html = generateResultsHtml([
        { file: 'a.cfm', line: 1, rule_id: 'R', severity: 'HIGH', description: 'x' }
    ]);
    assert.ok(!html.includes('Showing the first'));
});
