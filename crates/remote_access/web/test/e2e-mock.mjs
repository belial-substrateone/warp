// Manual end-to-end check of protocol.js against serve-mock.mjs using node's built-in WebSocket client.
//   node web/test/e2e-mock.mjs        (spawns the mock itself on a random port; needs local port binding)
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { pairDevice, RemoteClient, parsePairFragment } from '../js/protocol.js';

const port = 20000 + Math.floor(Math.random() * 20000);
const mock = spawn(process.execPath, [fileURLToPath(new URL('./serve-mock.mjs', import.meta.url)), '--port', String(port), '--approve-after', '1'], { stdio: ['ignore', 'pipe', 'inherit'] });
let log = '';
const ready = new Promise((r) => mock.stdout.on('data', (d) => { log += d; if (log.includes('Pairing URL')) r(); }));
await ready;
const base = `http://127.0.0.1:${port}`;
try {
  const frag = log.match(/#(v=1[^\s]+)/)[1];
  const parsed = parsePairFragment('#' + frag);
  assert.ok(parsed.ok);
  const res = await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'e2e', sleep: (ms) => new Promise((r) => setTimeout(r, ms)) });
  assert.equal(res.status, 'approved');
  const again = await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'e2e' });
  assert.equal(again.status, 'invalid'); // single use
  const c = new RemoteClient({ url: `ws://127.0.0.1:${port}/v1/ws`, token: res.token });
  let text = '';
  const done = new Promise((resolve) => {
    c.on('tree', (t) => { assert.equal(t.windows[0].tabs.length, 2); c.attach('pane:1'); });
    c.on('snapshot', (s) => { assert.equal(s.cols, 100); });
    c.on('output', ({ bytes }) => { text += new TextDecoder().decode(bytes); if (text.includes('$ ') && !text.includes('echoed')) { c.sendInput('hi\x1b[A\r'); text += 'echoed'; } if (text.includes('hi\x1b[33m<1b>')) resolve(); });
  });
  c.start();
  await Promise.race([done, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout; got ' + JSON.stringify(text))), 5000))]);
  const r = await c.action('tab.create');
  assert.equal(r.ok, true);
  const bad = new RemoteClient({ url: `ws://127.0.0.1:${port}/v1/ws`, token: 'wrong' });
  const fatal = new Promise((r) => bad.on('fatal', r));
  bad.start();
  assert.equal((await fatal).code, 4401);
  c.stop();
  console.log('e2e OK');
} finally { mock.kill(); }
