// Encrypts every report in reports-src/ into reports/index.html.
// The output only contains scrambled text; it can only be read with the R4 password.
// Password source (first match): env KVK_REPORTS_PASS, the file .reports-pass, or a prompt.
// reports-src/ and .reports-pass are in .gitignore and are never pushed.
import { readFileSync, writeFileSync, readdirSync, existsSync, mkdirSync } from 'node:fs';
import { webcrypto as crypto } from 'node:crypto';
import { createInterface } from 'node:readline';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const srcDir = join(root, 'reports-src');
const outDir = join(root, 'reports');
const passFile = join(root, '.reports-pass');
const ITER = 600000;

function ask(q, hidden) {
  return new Promise(res => {
    const rl = createInterface({ input: process.stdin, output: process.stdout, terminal: true });
    if (hidden) rl._writeToOutput = s => { if (s.startsWith(q)) rl.output.write(q); };
    rl.question(q, a => { rl.close(); if (hidden) process.stdout.write('\n'); res(a.trim()); });
  });
}

async function getPassword() {
  if (process.env.KVK_REPORTS_PASS) return process.env.KVK_REPORTS_PASS;
  if (existsSync(passFile)) return readFileSync(passFile, 'utf8').trim();
  const p1 = await ask('New R4 reports password: ', true);
  const p2 = await ask('Repeat password: ', true);
  if (!p1 || p1 !== p2) { console.error('Passwords empty or not the same. Nothing changed.'); process.exit(1); }
  if (p1.length < 10) console.warn('Tip: use at least 10 characters (e.g. three random words).');
  const save = await ask('Remember it on this Mac so next time no prompt? (y/n) ', false);
  if (save.toLowerCase().startsWith('y')) { writeFileSync(passFile, p1 + '\n', { mode: 0o600 }); console.log('Saved in .reports-pass (not pushed to GitHub).'); }
  return p1;
}

const files = readdirSync(srcDir).filter(f => f.endsWith('.html')).sort().reverse();
if (!files.length) { console.error('No reports in reports-src/.'); process.exit(1); }
const plain = files.map(f => readFileSync(join(srcDir, f), 'utf8')).join('\n<hr>\n');

const pass = await getPassword();
const enc = new TextEncoder();
const salt = crypto.getRandomValues(new Uint8Array(16));
const iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', enc.encode(pass), 'PBKDF2', false, ['deriveKey']);
const key = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: ITER, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(plain)));
const b64 = u => Buffer.from(u).toString('base64');
const payload = JSON.stringify({ v: 1, iter: ITER, salt: b64(salt), iv: b64(iv), ct: b64(ct) });

const tpl = readFileSync(join(root, 'tools', 'reports-template.html'), 'utf8');
mkdirSync(outDir, { recursive: true });
writeFileSync(join(outDir, 'index.html'), tpl.replace('__PAYLOAD__', payload));
console.log(`Encrypted ${files.length} report(s) into reports/index.html`);
