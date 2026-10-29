// End-to-end check of js/protocol.js against the real Rust server (`remote_devhost`) over TLS.
//   cargo build -p remote_access --features server,test-util --bin remote_devhost
//   node web/test/e2e-devhost.mjs [path/to/remote_devhost]
// The dev host uses a self-signed certificate, so this TEST (and only this test) disables
// certificate verification for node's fetch/WebSocket via NODE_TLS_REJECT_UNAUTHORIZED=0. Real
// clients pin the fingerprint from the QR payload instead.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { pairDevice, RemoteClient, parsePairFragment } from '../js/protocol.js';

const bin = process.argv[2] || fileURLToPath(new URL('../../../../target/debug/remote_devhost', import.meta.url));
const host = spawn(bin, ['--approve-after', '1'], { stdio: ['ignore', 'pipe', 'inherit'] });
let log = '';
const firstUrl = new Promise((resolve) => host.stdout.on('data', (d) => { log += d; const m = log.match(/PAIR_URL (\S+)/); if (m) resolve(m[1]); }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const within = (p, ms, what) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout: ' + what)), ms))]);

try {
  const url = new URL(await within(firstUrl, 10000, 'devhost start'));
  const base = url.origin; // https://127.0.0.1:port
  const wsUrl = `wss://${url.host}/v1/ws`;
  const parsed = parsePairFragment(url.hash);
  assert.ok(parsed.ok, JSON.stringify(parsed));

  // Static serving and info over TLS.
  for (const p of ['/', '/pair']) {
    const r = await fetch(base + p);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-type'), /text\/html/);
    assert.equal(r.headers.get('cache-control'), 'no-store');
    assert.match(r.headers.get('content-security-policy'), /default-src 'self'/);
  }
  assert.equal((await fetch(base + '/js/app.js')).headers.get('content-type').startsWith('text/javascript'), true);
  const info = await (await fetch(base + '/v1/info')).json();
  assert.equal(info.pairing, true);

  // Pairing (PC auto-approves after 1 s), single use.
  const paired = await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'node e2e', sleep });
  assert.equal(paired.status, 'approved', JSON.stringify(paired));
  assert.equal((await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'again', sleep })).status, 'invalid');

  // Session: tree, attach with replay, input echo, action.
  const open = (token) => {
    const c = new RemoteClient({ url: wsUrl, token });
    c.text = '';
    c.fatalP = new Promise((r) => c.on('fatal', r));
    c.on('output', ({ bytes }) => { c.text += new TextDecoder().decode(bytes); });
    c.on('tree', (t) => { if (!c.attached) { c.attached = true; c.attach('pane:1'); } });
    return c;
  };
  const waitText = async (c, needle, what) => { const t0 = Date.now(); while (!c.text.includes(needle)) { if (Date.now() - t0 > 5000) throw new Error(`timeout: ${what}; got ${JSON.stringify(c.text)}`); await sleep(25); } };

  const c = open(paired.token);
  let snapshot = null;
  c.on('snapshot', (s) => { snapshot = s; });
  c.start();
  await waitText(c, 'AnonWarp dev terminal', 'replay');
  assert.equal(snapshot.cols, 100);
  assert.equal(snapshot.rows, 30);
  assert.ok(c.text.startsWith('\x1bc'), 'replay starts with ESC c');
  c.sendInput('hi\x1b[A\r');
  await waitText(c, 'hi\x1b[33m<1b>\x1b[0m[A', 'echo');
  assert.equal((await c.action('tab.create')).ok, true);
  assert.equal((await c.action('instance.quit')).ok, false);

  // A bad token is refused with 4401.
  const bad = new RemoteClient({ url: wsUrl, token: 'nope' });
  const badFatal = new Promise((r) => bad.on('fatal', r));
  bad.start();
  assert.equal((await within(badFatal, 5000, 'bad token')).code, 4401);

  // Kill switch from the "PC": the dev host runs kill_all when "kill" is typed. Devices stay paired.
  c.sendInput('kill\r');
  assert.equal((await within(c.fatalP, 5000, 'kill')).code, 4403);
  const c2 = open(paired.token);
  c2.start();
  await waitText(c2, 'AnonWarp dev terminal', 'reconnect after kill');

  // Revocation: "revoke" revokes every device; the live socket and later reconnects get 4403.
  c2.sendInput('revoke\r');
  assert.equal((await within(c2.fatalP, 5000, 'revoke')).code, 4403);
  const c3 = open(paired.token);
  c3.start();
  assert.equal((await within(c3.fatalP, 5000, 'revoked token')).code, 4403);
  console.log('e2e-devhost OK');
} finally {
  host.kill();
}
process.exit(0);
