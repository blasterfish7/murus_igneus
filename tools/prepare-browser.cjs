/* Inflate open-source Chromium test assets without privileged ownership changes. SPDX-License-Identifier: MIT */
const fs = require('node:fs'), zlib = require('node:zlib'), cp = require('node:child_process'), path = require('node:path');
const root = path.resolve(process.argv[2]);
const source = path.join(root, 'node_modules/@sparticuz/chromium/bin'), target = path.join(root, 'bin');
fs.mkdirSync(target, { recursive: true });
fs.writeFileSync(path.join(target, 'chromium'), zlib.brotliDecompressSync(fs.readFileSync(path.join(source, 'chromium.br'))));
fs.chmodSync(path.join(target, 'chromium'), 0o755);
for (const name of ['swiftshader', 'fonts']) cp.execFileSync('tar', ['--no-same-owner', '-xf', '-', '-C', target], {
  input: zlib.brotliDecompressSync(fs.readFileSync(path.join(source, name + '.tar.br')))
});
