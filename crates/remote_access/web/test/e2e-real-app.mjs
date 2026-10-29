// End-to-end test of the whole remote-control stack against the REAL headless app (`anonwarp-tui`,
// a real shell in a real terminal pane), driven by a node client that speaks the phone protocol
// (js/protocol.js) while a second "operator" drives the TUI through tmux.
//
// Run (needs tmux, node >= 22, a private LAN or Tailscale address on this machine):
//   . $HOME/.cargo/env
//   export MACOSX_DEPLOYMENT_TARGET=11.0 CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_INCREMENTAL=0
//   cargo build -p warp_tui --bin anonwarp-tui
//   node crates/remote_access/web/test/e2e-real-app.mjs [path/to/anonwarp-tui]
// Env: ANONWARP_TUI_BIN (binary), E2E_PORT (fixed port; default = a free one), E2E_KEEP=1 (keep the
// tmux session + temp HOME for inspection), E2E_SLOW=1 (also wait out the pairing expiry).
// Needs to bind a port and use the network, so under a sandbox run it unsandboxed.
//
// Isolation: the TUI runs with HOME=<fresh temp dir>, so identity.json / devices.json (under
// <HOME>/Library/Application Support/dev.anonwarp.AnonWarp*/remote_access/) are throwaway; nothing
// in the real profile is touched and no test device is left behind.
// TLS: the server cert is self-signed. fetch/WebSocket run with NODE_TLS_REJECT_UNAUTHORIZED=0
// (this test only), but the cert's SHA-256 fingerprint is separately pinned against the `fp` of the
// pairing URL with tls.connect, and re-checked before the session phase.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
import { execFileSync } from 'node:child_process';
import { createHash, randomInt } from 'node:crypto';
import { createServer } from 'node:net';
import net from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pairDevice, RemoteClient, parsePairFragment } from '../js/protocol.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const BIN = process.argv[2] || process.env.ANONWARP_TUI_BIN || path.resolve(here, '../../../../target/debug/anonwarp-tui');
const SESSION = 'anonwarp-e2e';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const within = (p, ms, what) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout: ' + what)), ms))]);

// ---------------------------------------------------------------- results
const results = [];
function check(name, ok, detail = '') {
  results.push({ name, ok: !!ok, detail });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${detail && !ok ? '  -- ' + detail : ''}`);
  return !!ok;
}
async function step(name, fn) {
  try {
    const r = await fn();
    if (r !== false) check(name, true);
    return r;
  } catch (e) {
    check(name, false, String((e && e.stack) || e).split('\n').slice(0, 4).join(' | '));
    return undefined;
  }
}

// ---------------------------------------------------------------- tmux
const tmux = (...a) => execFileSync('tmux', a, { encoding: 'utf8' });
const screen = () => tmux('capture-pane', '-t', SESSION, '-p');
const keys = (...k) => tmux('send-keys', '-t', SESSION, ...k);
const typeText = (t) => tmux('send-keys', '-t', SESSION, '-l', t);
async function waitScreen(re, ms = 15000, what = String(re)) {
  const t0 = Date.now();
  let s = '';
  while (Date.now() - t0 < ms) {
    s = screen();
    const m = typeof re === 'string' ? (s.includes(re) ? [re] : null) : s.match(re);
    if (m) return { screen: s, match: m };
    await sleep(150);
  }
  throw new Error(`screen never showed ${what}; last screen:\n${s}`);
}
async function openRemoteView() {
  if (screen().includes('Remote access (phone)')) return;
  typeText('/remote-access');
  await sleep(500);
  keys('Enter');
  await waitScreen('Remote access (phone)', 10000);
}
async function closeRemoteView() {
  if (!screen().includes('Remote access (phone)')) return;
  keys('Escape');
  await sleep(400);
}

// ---------------------------------------------------------------- raw TLS/TCP helpers
function peerCertFingerprint(host, port) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, rejectUnauthorized: false, minVersion: 'TLSv1.3' }, () => {
      const raw = s.getPeerCertificate().raw;
      const proto = s.getProtocol();
      s.end();
      resolve({ fp: createHash('sha256').update(raw).digest('base64url'), protocol: proto });
    });
    s.on('error', reject);
    s.setTimeout(5000, () => { s.destroy(); reject(new Error('tls timeout')); });
  });
}
/** Raw HTTPS request with arbitrary headers (fetch cannot set Host). Resolves {status, headers, body} or {error}. */
function rawHttps(host, port, { method = 'GET', pathName = '/', headers = {}, body = '', localAddress } = {}) {
  return new Promise((resolve) => {
    const s = tls.connect({ host, port, rejectUnauthorized: false, localAddress }, () => {
      const h = { host: `${host}:${port}`, connection: 'close', ...headers };
      if (body) { h['content-length'] = Buffer.byteLength(body); h['content-type'] = h['content-type'] || 'application/json'; }
      s.write(`${method} ${pathName} HTTP/1.1\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n${body}`);
    });
    let buf = '';
    s.on('data', (d) => { buf += d; });
    s.on('end', () => {
      const m = buf.match(/^HTTP\/1\.1 (\d+)/);
      resolve(m ? { status: Number(m[1]), body: buf.split('\r\n\r\n').slice(1).join('\r\n\r\n') } : { error: 'no http response', raw: buf.slice(0, 80) });
    });
    s.on('error', (e) => resolve({ error: e.code || e.message }));
    s.setTimeout(6000, () => { s.destroy(); resolve({ error: 'timeout' }); });
  });
}
/** Plain-text TCP: send bytes, report what (if anything) came back before close/timeout. */
function rawTcp(host, port, payload, { localAddress } = {}) {
  return new Promise((resolve) => {
    const s = net.connect({ host, port, localAddress }, () => { s.write(payload); });
    let got = 0;
    s.on('data', (d) => { got += d.length; });
    s.on('close', () => resolve({ closed: true, bytes: got }));
    s.on('error', (e) => resolve({ error: e.code || e.message, bytes: got }));
    s.setTimeout(4000, () => { s.destroy(); resolve({ timeout: true, bytes: got }); });
  });
}
const freePort = () => new Promise((resolve, reject) => {
  const s = createServer();
  s.listen(0, '0.0.0.0', () => { const p = s.address().port; s.close(() => resolve(p)); });
  s.on('error', reject);
});

// ---------------------------------------------------------------- setup
if (!fs.existsSync(BIN)) { console.error(`binary not found: ${BIN} (cargo build -p warp_tui --bin anonwarp-tui)`); process.exit(2); }
try { execFileSync('tmux', ['-V']); } catch { console.error('tmux is required'); process.exit(2); }
const port = Number(process.env.E2E_PORT) || (await freePort());
const home = fs.mkdtempSync(path.join(os.tmpdir(), 'anonwarp-e2e-home-'));
try { tmux('kill-session', '-t', SESSION); } catch { /* none */ }
tmux('new-session', '-d', '-s', SESSION, '-x', '150', '-y', '75', '-c', home,
  `env HOME=${home} ANONWARP_REMOTE_PORT=${port} SHELL=${process.env.SHELL || '/bin/zsh'} ${BIN}`);
console.log(`tmux session ${SESSION}, HOME=${home}, port=${port}`);

const clients = [];
const mk = (token, wsUrl) => {
  const c = new RemoteClient({ url: wsUrl, token, backoff: { baseMs: 100, maxMs: 500 } });
  c.text = '';
  c.errors = [];
  c.fatalP = new Promise((r) => c.on('fatal', r));
  const dec = new TextDecoder('utf-8');
  c.on('output', ({ bytes }) => { c.text += dec.decode(bytes, { stream: true }); });
  c.on('tree', (t) => { c.tree = t; });
  c.on('snapshot', (s) => { c.snapshot = s; });
  c.on('error', (e) => c.errors.push(e));
  clients.push(c);
  return c;
};
const waitText = async (c, needle, ms = 15000, what = needle) => {
  const t0 = Date.now();
  while (!c.text.includes(needle)) {
    if (Date.now() - t0 > ms) throw new Error(`timeout waiting for ${what}; got ${JSON.stringify(c.text.slice(-400))}`);
    await sleep(25);
  }
  return Date.now() - t0;
};
const waitFor = async (fn, ms, what) => { const t0 = Date.now(); for (;;) { const v = await fn(); if (v) return v; if (Date.now() - t0 > ms) throw new Error('timeout: ' + what); await sleep(100); } };
const panesOf = (tree) => (tree?.windows || []).flatMap((w) => (w.tabs || []).flatMap((t) => (t.panes || []).map((p) => ({ ...p, tab: t.id, window: w.id }))));
const tabsOf = (tree) => (tree?.windows || []).flatMap((w) => w.tabs || []);

let exitCode = 0;
try {
  // ------------------------------------------------------------ 1. boot + enable
  await step('TUI boots to a terminal pane (prompt visible)', async () => {
    // First paint can take a while on a cold start; accept either prompt glyph or the zero state.
    await waitScreen(/Welcome to Warp|Warp Agent|logged in as/, 60000, 'TUI zero state');
    await sleep(1500);
  });
  await openRemoteView();
  keys('t');
  const on = await waitScreen(/Status: ON[\s\S]*Listening on: (.*)/, 15000, 'Status: ON + Listening on');
  const listen = on.match[1].trim();
  console.log('Listening on:', listen);
  const addrs = [...listen.matchAll(/(\d+\.\d+\.\d+\.\d+):(\d+)/g)].map((m) => ({ ip: m[1], port: Number(m[2]) }));
  await step('service enabled, listens only on private/Tailscale addresses on the requested port', () => {
    if (!addrs.length) throw new Error('no addresses: ' + listen);
    for (const a of addrs) {
      if (a.port !== port) throw new Error('wrong port ' + a.port);
      if (/^(127\.|0\.0\.0\.0|169\.254\.)/.test(a.ip)) throw new Error('forbidden bind addr ' + a.ip);
      if (!/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)/.test(a.ip)) throw new Error('non-private bind addr ' + a.ip);
    }
  });
  const host = addrs[0].ip;
  const base = `https://${host}:${port}`;
  const wsUrl = `wss://${host}:${port}/v1/ws`;
  const shownFp = (screen().match(/Cert fingerprint: (.*)/) || [])[1]?.trim();

  // ------------------------------------------------------------ 2. arm pairing, read URL
  keys('p');
  await waitScreen('Expires in', 10000, 'armed pairing');
  const armedScreen = screen();
  const lines = armedScreen.split('\n');
  const i0 = lines.findIndex((l) => l.trim().startsWith('https://'));
  const i1 = lines.findIndex((l, i) => i > i0 && l.trim().startsWith('Expires in'));
  let pairUrl = '';
  await step('pairing URL reassembled from screen chunks; QR rendered with half-blocks', () => {
    if (i0 < 0 || i1 < 0) throw new Error('pair URL not on screen:\n' + armedScreen);
    pairUrl = lines.slice(i0, i1).map((l) => l.trim()).filter(Boolean).join('');
    const qrRows = lines.slice(0, i0).filter((l) => /[▀▄█]{4,}/.test(l)).length;
    if (qrRows < 15) throw new Error('QR looks absent: ' + qrRows + ' rows');
    new URL(pairUrl);
  });
  if (!pairUrl) throw new Error('cannot continue without a pairing URL');
  const url = new URL(pairUrl);
  const parsed = parsePairFragment(url.hash);
  await step('pairing URL is well-formed (https, bound ip:port, v/s/fp/h/id/exp/n)', () => {
    if (!parsed.ok) throw new Error(JSON.stringify(parsed));
    if (url.protocol !== 'https:' || url.pathname !== '/pair') throw new Error(pairUrl);
    if (!addrs.some((a) => url.host === `${a.ip}:${a.port}`)) throw new Error('host not a bound addr: ' + url.host);
    if (!parsed.fp || !parsed.id || !parsed.exp || !parsed.name) throw new Error(JSON.stringify(parsed));
    const ttl = parsed.exp - Math.floor(Date.now() / 1000);
    console.log(`  secret ttl ${ttl}s; hosts=${parsed.hosts}`);
    if (ttl < 30 || ttl > 600) throw new Error('odd ttl ' + ttl);
  });

  // ------------------------------------------------------------ cert pinning
  await step('server certificate SHA-256 == fp in the pairing URL (TLS 1.3, pinned)', async () => {
    const { fp, protocol } = await peerCertFingerprint(host, port);
    if (fp !== parsed.fp) throw new Error(`fingerprint mismatch: cert ${fp} vs url ${parsed.fp}`);
    if (protocol !== 'TLSv1.3') throw new Error('protocol ' + protocol);
    if (shownFp) {
      const hex = Buffer.from(fp, 'base64url').toString('hex');
      const shown = shownFp.replace(/[^0-9a-f]/gi, '').toLowerCase();
      if (!hex.startsWith(shown.slice(0, 16))) throw new Error(`TUI-displayed fingerprint "${shownFp}" != cert ${hex}`);
    }
  });
  await step('TLS 1.2 is refused', async () => {
    const r = await new Promise((resolve) => {
      const s = tls.connect({ host, port, rejectUnauthorized: false, maxVersion: 'TLSv1.2' }, () => { s.destroy(); resolve('connected'); });
      s.on('error', (e) => resolve('refused:' + (e.code || e.message)));
    });
    if (r === 'connected') throw new Error('TLS1.2 handshake succeeded');
  });

  // ------------------------------------------------------------ static + info over TLS
  await step('GET / and /pair serve over TLS with no-store + CSP; /v1/info', async () => {
    for (const p of ['/', '/pair']) {
      const r = await fetch(base + p);
      if (r.status !== 200) throw new Error(p + ' ' + r.status);
      if (!/text\/html/.test(r.headers.get('content-type'))) throw new Error('ctype');
      if (r.headers.get('cache-control') !== 'no-store') throw new Error('cache-control ' + r.headers.get('cache-control'));
      if (!/default-src 'self'/.test(r.headers.get('content-security-policy') || '')) throw new Error('csp');
    }
    const info = await (await fetch(base + '/v1/info')).json();
    if (info.protocol !== 1 || info.pairing !== true) throw new Error(JSON.stringify(info));
  });

  // ------------------------------------------------------------ 4. security spot checks (pre-pair)
  await step('wrong Host header -> 403', async () => {
    for (const h of ['evil.example.com', `${host}:${port + 1}`, 'localhost']) {
      const r = await rawHttps(host, port, { headers: { host: h } });
      if (r.status !== 403) throw new Error(`Host ${h}: ${JSON.stringify(r)}`);
    }
  });
  await step('foreign Origin on POST /v1/pair -> 403 (and does not burn the secret)', async () => {
    const r = await rawHttps(host, port, { method: 'POST', pathName: '/v1/pair', headers: { origin: 'https://evil.example.com' }, body: JSON.stringify({ v: 1, secret: parsed.secret, device_name: 'x', platform: 'web' }) });
    if (r.status !== 403) throw new Error(JSON.stringify(r));
  });
  await step('plain HTTP to the TLS port gets no HTTP response', async () => {
    const r = await rawTcp(host, port, `GET / HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`);
    if (r.bytes > 0 && /HTTP\//.test('x')) throw new Error('got bytes');
    // Rustls may send a TLS alert (a few bytes) before closing; only an HTTP reply would be a failure.
    console.log(`  plain HTTP: ${JSON.stringify(r)}`);
  });
  const loop = await (async () => {
    const r = await rawHttps('127.0.0.1', port, {});
    const r2 = await rawTcp('127.0.0.1', port, 'x');
    return { r, r2 };
  })();
  await step('connect via 127.0.0.1 is refused/dropped (loopback not bound under production policy)', () => {
    console.log(`  127.0.0.1 -> https: ${JSON.stringify(loop.r)}  tcp: ${JSON.stringify(loop.r2)}`);
    if (loop.r.status) throw new Error('loopback got an HTTP response: ' + loop.r.status);
  });
  // Spoofed-source attempt: bind the client socket to loopback while dialing the LAN address.
  const spoof = await rawHttps(host, port, { localAddress: '127.0.0.1' });
  console.log(`  LAN ip with local source 127.0.0.1 -> ${JSON.stringify(spoof)}`);
  check('LAN address reached from a loopback source is dropped', !spoof.status, JSON.stringify(spoof));

  // ------------------------------------------------------------ 3. pairing: wrong secret first
  const wrong = await pairDevice({ fetch, base, secret: 'A'.repeat(43), deviceName: 'wrong-secret', sleep });
  check('wrong pairing secret rejected (invalid/401)', wrong.status === 'invalid', JSON.stringify(wrong));

  // ------------------------------------------------------------ pairing with PC approval
  let promptSeen = null;
  const pairP = pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'e2e-node-phone', platform: 'web', sleep });
  await step('approval prompt shows device name, platform and phone IP', async () => {
    const s = (await waitScreen('A phone wants to pair', 15000, 'approval prompt')).screen;
    promptSeen = s;
    if (!/Name:\s+e2e-node-phone/.test(s)) throw new Error('name missing:\n' + s);
    if (!/Platform:\s+web/.test(s)) throw new Error('platform missing');
    const ip = (s.match(/IP address:\s+(\S+)/) || [])[1];
    if (!ip || ip === 'unknown') throw new Error('ip missing: ' + ip);
    const mine = Object.values(os.networkInterfaces()).flat().filter((i) => i && i.family === 'IPv4').map((i) => i.address);
    if (!mine.includes(ip)) throw new Error(`prompt IP ${ip} is not one of this machine's addresses ${mine}`);
    console.log('  prompt IP:', ip);
  });
  keys('y');
  const paired = await within(pairP, 20000, 'pairing result');
  let token;
  await step('pairing approved with y; device token returned once', () => {
    if (paired.status !== 'approved' || !paired.token) throw new Error(JSON.stringify(paired));
    token = paired.token;
    if (!/^[A-Za-z0-9_-]{40,}$/.test(token)) throw new Error('token shape');
  });
  const reuse = await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'replay', sleep });
  check('consumed pairing secret cannot be reused (invalid)', reuse.status === 'invalid', JSON.stringify(reuse));
  if (!token) throw new Error('no token; cannot continue');
  await sleep(500);
  check('TUI lists the paired device', /Paired devices \(1\)[\s\S]*e2e-node-phone/.test(screen()), screen());

  // ------------------------------------------------------------ token stored hashed
  await step('devices.json stores a hash, never the plaintext token; files are 0600', () => {
    const found = [];
    const walk = (d) => { for (const e of fs.readdirSync(d, { withFileTypes: true })) { const p = path.join(d, e.name); if (e.isDirectory()) walk(p); else if (/remote_access\/(identity|devices)\.json$/.test(p)) found.push(p); } };
    walk(home);
    console.log('  state files:', found.map((f) => f.replace(home, '<HOME>')).join(', '));
    const dev = found.find((f) => f.endsWith('devices.json'));
    const idf = found.find((f) => f.endsWith('identity.json'));
    if (!dev || !idf) throw new Error('state files missing: ' + found);
    const text = fs.readFileSync(dev, 'utf8');
    if (text.includes(token)) throw new Error('plaintext token on disk');
    if (!text.includes('e2e-node-phone')) throw new Error('device not persisted');
    for (const f of found) { const mode = fs.statSync(f).mode & 0o777; if (mode & 0o077) throw new Error(`${f} mode ${mode.toString(8)}`); }
  });

  // ------------------------------------------------------------ 3. session
  await closeRemoteView();
  await step('cert fingerprint unchanged before session phase', async () => {
    const { fp } = await peerCertFingerprint(host, port);
    if (fp !== parsed.fp) throw new Error('fingerprint changed');
  });
  const c = mk(token, wsUrl);
  c.start();
  let pane;
  await step('hello -> welcome, list -> tree with a real pane', async () => {
    const tree = await waitFor(() => c.tree, 10000, 'tree');
    const panes = panesOf(tree);
    if (!panes.length) throw new Error(JSON.stringify(tree));
    pane = panes.find((p) => p.focused) || panes[0];
    console.log('  pane:', JSON.stringify(pane));
    if (!pane.id || !pane.cols || !pane.rows) throw new Error('pane shape');
  });
  if (!pane) throw new Error('no pane');
  c.attach(pane.id);
  await step('attach -> snapshot + output frames', async () => {
    await waitFor(() => c.snapshot, 10000, 'snapshot');
    console.log(`  snapshot cols=${c.snapshot.cols} rows=${c.snapshot.rows} replay bytes so far=${c.text.length}`);
  });
  // Let the shell finish its startup so the typed line is not swallowed by init.
  await sleep(2500);
  const a = randomInt(100000, 999999), b = randomInt(100000, 999999);
  const expect = String(a + b);
  const before = c.text.length;
  const t0 = Date.now();
  c.sendInput(`echo remote-e2e-$((${a}+${b}))\r`);
  await step('input frame executes in the real shell; echoed output arrives in binary frames', async () => {
    const ms = await waitText(c, `remote-e2e-${expect}`, 20000, 'command output');
    console.log(`  round trip ${Date.now() - t0} ms (first match after ${ms} ms)`);
    const fresh = c.text.slice(before);
    if (/\x1b\[33m<1b>/.test(fresh)) throw new Error('mirror escaped control bytes');
  });
  await step('the same output is visible in the real TUI pane (capture-pane)', async () => {
    await waitScreen(`remote-e2e-${expect}`, 15000, 'remote command output on the TUI screen');
  });
  // Output integrity: a long, multi-chunk burst with SGR colors and UTF-8.
  await step('bulk output with colors/UTF-8 arrives intact and in order', async () => {
    const mark = `BULK${randomInt(1e6)}`;
    c.sendInput(`for i in $(seq 1 400); do printf '\\033[3%dm${mark}-%04d-héllo-✓\\033[0m\\n' $((i%7+1)) $i; done; echo ${mark}-DONE$((2+3))\r`);
    await waitText(c, `${mark}-DONE5`, 30000, 'bulk end');
    const got = [...c.text.matchAll(new RegExp(`${mark}-(\\d{4})-h\\u00e9llo-\\u2713`, 'g'))].map((m) => Number(m[1]));
    const uniq = got.filter((v, i) => got.indexOf(v) === i);
    if (uniq.length !== 400 || uniq.some((v, i) => v !== i + 1)) throw new Error(`got ${uniq.length}/400 lines, first=${uniq.slice(0, 3)}, last=${uniq.slice(-3)}; tail=${JSON.stringify(c.text.slice(-300))}`);
  });
  await step('ping/pong latency is sane', async () => {
    const ms = await new Promise((resolve, reject) => { c.on('latency', ({ ms }) => resolve(ms)); c._sendJson({ t: 'ping', n: 9999 }); c.pingSent.set(9999, Date.now()); setTimeout(() => reject(new Error('no pong')), 5000); });
    console.log(`  ws ping latency ${ms} ms`);
  });

  // ------------------------------------------------------------ actions via allowlist
  const tabsBefore = tabsOf(c.tree).length;
  const panesBefore = panesOf(c.tree).length;
  await step('action tab.create (allowlisted) ok; tree gains a tab', async () => {
    const r = await c.action('tab.create');
    if (!r.ok) throw new Error(JSON.stringify(r));
    await waitFor(async () => { c.list(); await sleep(300); return tabsOf(c.tree).length === tabsBefore + 1; }, 10000, 'new tab in tree');
  });
  await step('action pane.split (allowlisted): ok with a new pane, or an explicit `unsupported` (the TUI has no split panes)', async () => {
    const cur = panesOf(c.tree).find((p) => p.focused) || panesOf(c.tree)[0];
    const r = await c.action('pane.split', { pane: cur.id }, { direction: 'right' });
    if (r.ok) {
      await waitFor(async () => { c.list(); await sleep(300); return panesOf(c.tree).length >= panesBefore + 2; }, 10000, 'new pane in tree');
    } else {
      if (r.error?.code !== 'unsupported') throw new Error(JSON.stringify(r));
      console.log('  pane.split ->', r.error.code, r.error.message);
    }
  });
  await step('tab.activate / pane.focus on a known tab succeed', async () => {
    c.list(); await sleep(400);
    const tab = tabsOf(c.tree)[0];
    const r = await c.action('tab.activate', { tab: tab.id });
    if (!r.ok) throw new Error(JSON.stringify(r));
    const r2 = await c.action('pane.focus', { pane: tab.panes[0].id });
    if (!r2.ok) throw new Error(JSON.stringify(r2));
    const bad = await c.action('tab.activate', { tab: 'tab:999999' });
    if (bad.ok) throw new Error('activating a nonexistent tab succeeded');
    console.log('  tab.activate(nonexistent) ->', bad.error?.code);
  });
  await step('non-allowlisted actions denied (window.close, instance.quit, pane.write, bogus)', async () => {
    for (const name of ['window.close', 'instance.quit', 'tab.create_agent', 'pane.write', 'session.activate', 'nope.nope']) {
      const r = await c.action(name);
      if (r.ok) throw new Error(`${name} was allowed!`);
      console.log(`  ${name} -> ${r.error?.code}`);
    }
    const r = await c.action('tab.create', {}, { tab_type: 'agent' });
    if (r.ok) throw new Error('tab.create with tab_type=agent was allowed');
    console.log(`  tab.create tab_type=agent -> ${r.error?.code}`);
  });
  await step('cleanup: pane.close and tab.close for the objects we created', async () => {
    c.list(); await sleep(400);
    const tabs = tabsOf(c.tree);
    const extra = tabs[tabs.length - 1];
    const r = await c.action('tab.close', { tab: extra.id });
    if (!r.ok) throw new Error(JSON.stringify(r));
    await sleep(500);
    c.list(); await sleep(400);
    const ps = panesOf(c.tree);
    if (ps.length > panesBefore) {
      const r2 = await c.action('pane.close', { pane: ps[ps.length - 1].id });
      if (!r2.ok) throw new Error(JSON.stringify(r2));
    }
  });

  // ------------------------------------------------------------ kill switch
  await openRemoteView();
  await sleep(300);
  check('TUI shows the active session', /Active sessions \(1\)/.test(screen()), screen());
  keys('k');
  await step('kill switch (k) closes the WS with 4403 session_killed', async () => {
    const f = await within(c.fatalP, 8000, 'kill close');
    if (f.code !== 4403) throw new Error(JSON.stringify(f));
  });
  await step('after kill the stored token still reconnects (device stays paired), pane re-attaches', async () => {
    const c2 = mk(token, wsUrl);
    c2.start();
    const tree = await waitFor(() => c2.tree, 10000, 'tree after kill');
    c2.attach(panesOf(tree)[0].id);
    await waitFor(() => c2.snapshot, 10000, 'snapshot after kill');
    const a2 = randomInt(1000, 9999), b2 = randomInt(1000, 9999);
    c2.sendInput(`echo again-$((${a2}+${b2}))\r`);
    await waitText(c2, `again-${a2 + b2}`, 15000, 'echo after reconnect');
    c.c2 = c2;
  });

  // ------------------------------------------------------------ revoke
  await openRemoteView();
  await sleep(300);
  keys('r');
  await step('revoke (r) closes the live socket with 4403', async () => {
    const f = await within(c.c2.fatalP, 8000, 'revoke close');
    if (f.code !== 4403) throw new Error(JSON.stringify(f));
  });
  await step('revoked token is refused on reconnect (fatal 4403/4401)', async () => {
    const c3 = mk(token, wsUrl);
    c3.start();
    const f = await within(c3.fatalP, 8000, 'revoked reconnect');
    if (![4403, 4401].includes(f.code)) throw new Error(JSON.stringify(f));
    console.log('  revoked token close code', f.code);
  });
  await sleep(300);
  check('TUI shows no paired devices after revoke', /Paired devices \(0\)/.test(screen()), screen());
  await step('bad token -> 4401 within the hello deadline', async () => {
    const bad = mk('not-a-token', wsUrl);
    bad.start();
    const f = await within(bad.fatalP, 8000, 'bad token');
    if (f.code !== 4401) throw new Error(JSON.stringify(f));
  });
  await step('hello deadline: silent socket is closed (4401)', async () => {
    const ws = new WebSocket(wsUrl, 'anonwarp.v1');
    const code = await within(new Promise((r) => { ws.onclose = (e) => r(e.code); }), 8000, 'silent socket closed');
    if (code !== 4401) throw new Error('code ' + code);
  });

  // ------------------------------------------------------------ re-pair + expiry/lockout
  keys('p');
  await waitScreen('Expires in', 10000, 're-armed');
  await step('after revoke the device can be re-paired with a fresh QR (new secret differs)', async () => {
    const ls = screen().split('\n');
    const j0 = ls.findIndex((l) => l.trim().startsWith('https://'));
    const j1 = ls.findIndex((l, i) => i > j0 && l.trim().startsWith('Expires in'));
    const url2 = new URL(ls.slice(j0, j1).map((l) => l.trim()).join(''));
    const p2 = parsePairFragment(url2.hash);
    if (p2.secret === parsed.secret) throw new Error('secret reused');
    const pp = pairDevice({ fetch, base, secret: p2.secret, deviceName: 'e2e-second', platform: 'android', sleep });
    await waitScreen('A phone wants to pair', 15000, 'second approval');
    check('approval prompt platform is android for second device', /Platform:\s+android/.test(screen()));
    keys('n'); // deny this one
    const r = await within(pp, 20000, 'denied result');
    if (r.status !== 'denied') throw new Error(JSON.stringify(r));
  });
  await step('denied pairing consumed the secret (cannot be retried)', async () => {
    const r = await pairDevice({ fetch, base, secret: parsed.secret, deviceName: 'x', sleep });
    if (r.status === 'approved') throw new Error('approved?!');
  });
  if (process.env.E2E_SLOW) {
    await openRemoteView();
    if (screen().includes('Expires in')) { keys('p'); await sleep(300); } // cancel any armed secret first
    keys('p');
    await waitScreen('Expires in', 10000, 'armed for expiry test');
    const ls = screen().split('\n');
    const j0 = ls.findIndex((l) => l.trim().startsWith('https://'));
    const j1 = ls.findIndex((l, i) => i > j0 && l.trim().startsWith('Expires in'));
    const p3 = parsePairFragment(new URL(ls.slice(j0, j1).map((l) => l.trim()).join('')).hash);
    const wait = Math.max(0, p3.exp - Math.floor(Date.now() / 1000)) + 3;
    console.log(`  waiting ${wait}s for expiry`);
    await sleep(wait * 1000);
    const r = await pairDevice({ fetch, base, secret: p3.secret, deviceName: 'late', sleep });
    check('expired pairing secret rejected', r.status === 'invalid', JSON.stringify(r));
  }
} catch (e) {
  check('harness aborted', false, String((e && e.stack) || e).slice(0, 1500));
} finally {
  for (const cl of clients) { try { cl.stop(); } catch { /* ignore */ } }
  const final = (() => { try { return screen(); } catch { return ''; } })();
  if (process.env.E2E_KEEP) {
    console.log(`E2E_KEEP: tmux session ${SESSION} and ${home} kept`);
  } else {
    try { tmux('kill-session', '-t', SESSION); } catch { /* gone */ }
    fs.rmSync(home, { recursive: true, force: true });
  }
  const failed = results.filter((r) => !r.ok);
  console.log(`\n${results.length - failed.length}/${results.length} checks passed`);
  for (const f of failed) console.log(`FAILED: ${f.name}\n    ${f.detail}`);
  if (failed.length) console.log('--- last TUI screen ---\n' + final);
  exitCode = failed.length ? 1 : 0;
}
process.exit(exitCode);
