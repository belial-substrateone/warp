#!/usr/bin/env node
// Dependency-free mock of the AnonWarp remote-access server for manual browser testing.
//   node web/test/serve-mock.mjs [--port 8787] [--approve-after 3] [--pair-timeout]
// Plain HTTP + ws:// (no TLS) on 127.0.0.1; localhost is a secure context so clipboard etc. work.
// Implements: static files, GET /v1/info, POST /v1/pair, GET /v1/pair/<id> (long-poll), POST /v1/revoke,
// GET /v1/ws (RFC 6455 handshake + framing written by hand) speaking the anonwarp.v1 frame protocol.
// Typing "revoke<Enter>" in the terminal closes the socket with 4403; "kill<Enter>" sends session_killed first.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { encodeOutputFrame, decodeBinaryFrame } from '../js/protocol.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const opt = (n, d) => { const i = args.indexOf(n); return i >= 0 ? args[i + 1] : d; };
const PORT = Number(opt('--port', 8787));
const APPROVE_AFTER_S = Number(opt('--approve-after', 3));
const SECRET = 'mock-secret-mock-secret-mock-secret-1234567';

const state = {
  armed: true, failures: 0, pending: new Map(), tokens: new Set(), sockets: new Set(),
};

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.webmanifest': 'application/manifest+json', '.svg': 'image/svg+xml', '.png': 'image/png', '.map': 'application/json' };
const CSP = "default-src 'self'; script-src 'self'; connect-src 'self' wss:; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'";

function json(res, status, body) {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}
async function readBody(req) { const c = []; for await (const d of req) c.push(d); try { return JSON.parse(Buffer.concat(c).toString() || '{}'); } catch { return {}; } }

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  if (p === '/v1/info') return json(res, 200, { protocol: 1, instance: 'mock', name: 'MockPC', pairing: state.armed });
  if (p === '/v1/pair' && req.method === 'POST') {
    const b = await readBody(req);
    if (b.secret !== SECRET || !state.armed) { state.failures++; return json(res, 401, {}); }
    state.armed = false; // single use
    const id = crypto.randomBytes(8).toString('hex');
    const token = crypto.randomBytes(32).toString('base64url');
    const rec = { token, status: 'pending', waiters: [] };
    state.pending.set(id, rec);
    console.log(`[pair] request from "${b.device_name}" (${b.platform}); auto-approving in ${APPROVE_AFTER_S}s`);
    if (!args.includes('--pair-timeout')) {
      setTimeout(() => { rec.status = 'approved'; state.tokens.add(token); rec.waiters.splice(0).forEach((f) => f()); }, APPROVE_AFTER_S * 1000);
    }
    return json(res, 200, { status: 'pending', poll: id });
  }
  const m = p.match(/^\/v1\/pair\/([^/]+)$/);
  if (m && req.method === 'GET') {
    const rec = state.pending.get(decodeURIComponent(m[1]));
    if (!rec) return json(res, 404, {});
    const reply = () => {
      if (rec.status === 'approved' && !rec.delivered) { rec.delivered = true; return json(res, 200, { status: 'approved', device_id: 'dev-' + m[1].slice(0, 4), token: rec.token }); }
      return json(res, 200, { status: rec.delivered ? 'expired' : 'pending' });
    };
    if (rec.status !== 'pending') return reply();
    const t = setTimeout(() => { rec.waiters = rec.waiters.filter((f) => f !== w); reply(); }, 25000);
    const w = () => { clearTimeout(t); reply(); };
    rec.waiters.push(w);
    return;
  }
  if (p === '/v1/revoke' && req.method === 'POST') {
    const tok = (req.headers.authorization || '').replace(/^Bearer /, '');
    state.tokens.delete(tok);
    console.log('[revoke] device unpaired itself');
    return json(res, 200, {});
  }
  // static
  let rel = p === '/' || p === '/pair' || p === '/pair/' ? '/index.html' : decodeURIComponent(p);
  const file = path.normalize(path.join(ROOT, rel));
  if (!file.startsWith(ROOT + path.sep) || file.startsWith(path.join(ROOT, 'test'))) { res.writeHead(404); return res.end('not found'); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    res.writeHead(200, { 'content-type': MIME[path.extname(file)] || 'application/octet-stream', 'cache-control': 'no-store', 'content-security-policy': CSP, 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' });
    res.end(data);
  });
});

// ------------------------------------------------------------------ minimal RFC 6455
const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function frame(opcode, payload) {
  const len = payload.length;
  let head;
  if (len < 126) head = Buffer.from([0x80 | opcode, len]);
  else if (len < 65536) { head = Buffer.alloc(4); head[0] = 0x80 | opcode; head[1] = 126; head.writeUInt16BE(len, 2); }
  else { head = Buffer.alloc(10); head[0] = 0x80 | opcode; head[1] = 127; head.writeBigUInt64BE(BigInt(len), 2); }
  return Buffer.concat([head, payload]);
}

class Conn {
  constructor(socket) { this.s = socket; this.buf = Buffer.alloc(0); this.frag = null; this.onmsg = () => {}; this.onclose = () => {}; this.closed = false;
    socket.on('data', (d) => { this.buf = Buffer.concat([this.buf, d]); this.parse(); });
    socket.on('close', () => this.end()); socket.on('error', () => this.end()); }
  end() { if (!this.closed) { this.closed = true; this.onclose(); } }
  sendText(s) { this.s.write(frame(0x1, Buffer.from(s))); }
  sendBinary(b) { this.s.write(frame(0x2, Buffer.from(b))); }
  ping() { this.s.write(frame(0x9, Buffer.alloc(0))); }
  close(code, reason = '') { if (this.closed) return; const b = Buffer.alloc(2 + Buffer.byteLength(reason)); b.writeUInt16BE(code, 0); b.write(reason, 2); this.s.write(frame(0x8, b)); setTimeout(() => this.s.destroy(), 200); }
  parse() {
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = !!(b0 & 0x80), op = b0 & 0x0f, masked = !!(b1 & 0x80);
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; len = Number(this.buf.readBigUInt64BE(2)); off = 10; }
      if (len > 1 << 20) { this.s.destroy(); return; }
      const need = off + (masked ? 4 : 0) + len;
      if (this.buf.length < need) return;
      let payload = this.buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const mk = this.buf.subarray(off, off + 4); payload = Buffer.from(payload.map((v, i) => v ^ mk[i & 3])); }
      this.buf = this.buf.subarray(need);
      if (op === 0x8) { this.s.write(frame(0x8, payload.subarray(0, 2))); this.s.end(); this.end(); return; }
      if (op === 0x9) { this.s.write(frame(0xA, payload)); continue; }
      if (op === 0xA) continue;
      if (op === 0x1 || op === 0x2) this.frag = { op, parts: [payload] };
      else if (op === 0x0 && this.frag) this.frag.parts.push(payload);
      if (fin && this.frag) { const f = this.frag; this.frag = null; const data = Buffer.concat(f.parts); this.onmsg(f.op === 0x1 ? data.toString() : data); }
    }
  }
}

// ------------------------------------------------------------------ canned terminal session
const PANES = {
  'pane:1': { title: 'zsh', cwd: '~/projects', cols: 100, rows: 30 },
  'pane:2': { title: 'logs', cwd: '/var/log', cols: 80, rows: 24 },
  'pane:3': { title: 'htop', cwd: '~', cols: 80, rows: 24 },
};
const TREE = { t: 'tree', windows: [{ id: 'win:1', title: 'AnonWarp', tabs: [
  { id: 'tab:1', title: 'dev', active: true, panes: [{ id: 'pane:1', session: 's1', title: 'zsh', cwd: '~/projects', cols: 100, rows: 30, alt_screen: false, focused: true }, { id: 'pane:2', session: 's2', title: 'logs', cwd: '/var/log', cols: 80, rows: 24, alt_screen: false, focused: false }] },
  { id: 'tab:2', title: 'monitor', active: false, panes: [{ id: 'pane:3', session: 's3', title: 'htop', cwd: '~', cols: 80, rows: 24, alt_screen: false, focused: true }] },
] }] };

const PROMPT = '\x1b[32muser@mockpc\x1b[0m:\x1b[34m~\x1b[0m$ ';
const BANNER = (pane) => `\x1b[1;36mAnonWarp mock terminal\x1b[0m  (${pane})\r\nType anything. Control bytes are shown as <hex>. Try Esc, Tab, arrows, Ctrl toggle.\r\nType "revoke" or "kill" + Enter to test the 4403 screen, "big" for a lot of output.\r\n`;

function handleSocket(conn, req) {
  let authed = false;
  let attach = null; // {pane, offset}
  let line = '';
  const send = (o) => conn.sendText(JSON.stringify(o));
  const out = (str) => {
    if (!attach) return;
    const b = Buffer.from(str);
    conn.sendBinary(encodeOutputFrame(attach.stream, attach.offset, b));
    attach.offset += b.length;
  };
  const authTimer = setTimeout(() => { if (!authed) conn.close(4401, 'hello timeout'); }, 3000);
  const hb = setInterval(() => conn.ping(), 15000);
  state.sockets.add(conn);
  conn.onclose = () => { clearTimeout(authTimer); clearInterval(hb); state.sockets.delete(conn); };

  conn.onmsg = (m) => {
    if (typeof m !== 'string') {
      const f = decodeBinaryFrame(new Uint8Array(m));
      if (!authed || !f || f.kind !== 'input' || !attach) return;
      for (const byte of f.payload) {
        if (byte === 0x0d) { out('\r\n'); const cmd = line.trim(); line = '';
          if (cmd === 'revoke') { conn.close(4403, 'revoked'); return; }
          if (cmd === 'kill') { send({ t: 'session_killed', reason: 'Killed from the PC (mock)' }); conn.close(4403, 'killed'); return; }
          if (cmd === 'big') { for (let i = 0; i < 300; i++) out(`line ${i} ${'x'.repeat(i % 60)}\r\n`); }
          out(PROMPT); }
        else if (byte === 0x7f) { if (line.length) { line = line.slice(0, -1); out('\b \b'); } }
        else if (byte >= 0x20 && byte < 0x7f) { line += String.fromCharCode(byte); out(String.fromCharCode(byte)); }
        else if (byte >= 0x80) { out(String.fromCharCode(byte)); }
        else out(`\x1b[33m<${byte.toString(16).padStart(2, '0')}>\x1b[0m`);
      }
      return;
    }
    let msg; try { msg = JSON.parse(m); } catch { return; }
    if (!authed) {
      if (msg.t !== 'hello' || !state.tokens.has(msg.token)) { conn.close(4401, 'auth failed'); return; }
      authed = true; clearTimeout(authTimer);
      send({ t: 'welcome', v: 1, device: 'mock-device', server: 'anonwarp-mock 0.0', limits: { max_binary_frame: 262144 }, phone_resize: args.includes('--phone-resize') });
      return;
    }
    switch (msg.t) {
      case 'list': send(TREE); break;
      case 'attach': {
        const meta = PANES[msg.pane];
        if (!meta) { send({ t: 'error', code: 'no_such_pane', message: 'unknown pane' }); break; }
        attach = { pane: msg.pane, stream: msg.stream, offset: 1000 };
        send({ t: 'snapshot', pane: msg.pane, cols: meta.cols, rows: meta.rows, alt_screen: false, offset: attach.offset });
        out('\x1bc'); out(BANNER(msg.pane)); out(PROMPT);
        break;
      }
      case 'detach': attach = null; break;
      case 'ping': send({ t: 'pong', n: msg.n }); break;
      case 'resize': send({ t: 'error', code: 'resize_denied', message: 'phone resize not allowed' }); break;
      case 'action': send({ t: 'result', id: msg.id, ok: true, data: {} }); console.log('[action]', msg.name, JSON.stringify(msg.target)); break;
      case 'ack': break;
      default: send({ t: 'error', code: 'unknown_type', message: String(msg.t).slice(0, 40) });
    }
  };
}

server.on('upgrade', (req, socket) => {
  const url = new URL(req.url, 'http://x');
  const key = req.headers['sec-websocket-key'];
  if (url.pathname !== '/v1/ws' || !key || (req.headers.upgrade || '').toLowerCase() !== 'websocket') { socket.destroy(); return; }
  const offered = (req.headers['sec-websocket-protocol'] || '').split(',').map((s) => s.trim());
  const accept = crypto.createHash('sha1').update(key + WS_GUID).digest('base64');
  socket.write(['HTTP/1.1 101 Switching Protocols', 'Upgrade: websocket', 'Connection: Upgrade', `Sec-WebSocket-Accept: ${accept}`, offered.includes('anonwarp.v1') ? 'Sec-WebSocket-Protocol: anonwarp.v1' : '', '', ''].filter((l, i, a) => l !== '' || i >= a.length - 2).join('\r\n'));
  handleSocket(new Conn(socket), req);
});

server.listen(PORT, '127.0.0.1', () => {
  const fp = crypto.createHash('sha256').update('mock-cert').digest('base64url');
  const exp = Math.floor(Date.now() / 1000) + 3600;
  console.log(`Mock AnonWarp server on http://127.0.0.1:${PORT}`);
  console.log(`Pairing URL (single use; restart the server for another):\n  http://127.0.0.1:${PORT}/pair#v=1&s=${SECRET}&fp=${fp}&h=127.0.0.1&id=mock&exp=${exp}&n=MockPC`);
  console.log(`Main page: http://127.0.0.1:${PORT}/   (state resets on restart: tokens are in memory, so after restart the 4401 screen appears)`);
  console.log('Flags: --port N  --approve-after SECONDS  --pair-timeout (never approve)  --phone-resize');
});
