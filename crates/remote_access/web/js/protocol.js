// anonwarp-remote v1 protocol client. NO DOM dependencies: everything environment-specific
// (fetch, WebSocket, timers, randomness) is injectable so this runs under `node --test`.

export const PROTOCOL_VERSION = 1;
export const SUBPROTOCOL = 'anonwarp.v1';

export const FRAME_OUTPUT = 0x01;
export const FRAME_INPUT = 0x02;
export const MAX_INPUT_PAYLOAD = 60 * 1024; // spec: input frame <= 64 KiB incl. header; stay safely below
export const ACK_EVERY = 256 * 1024;

export const CLOSE = Object.freeze({
  BAD_REQUEST: 4400,
  AUTH: 4401,
  KILLED: 4403,
  IDLE: 4408,
  RATE_LIMITED: 4429,
});

const encoder = new TextEncoder();

// ---------------------------------------------------------------------------------------------
// Binary frames: [0x01 output | 0x02 input][u32 BE stream][ (output only) u64 BE offset ][payload]
// ---------------------------------------------------------------------------------------------

export function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (typeof data === 'string') return encoder.encode(data);
  throw new TypeError('expected string, Uint8Array or ArrayBuffer');
}

export function encodeInputFrame(streamId, data) {
  const payload = toBytes(data);
  const out = new Uint8Array(5 + payload.length);
  const dv = new DataView(out.buffer);
  out[0] = FRAME_INPUT;
  dv.setUint32(1, streamId >>> 0, false);
  out.set(payload, 5);
  return out;
}

export function encodeOutputFrame(streamId, offset, data) {
  // Used by tests and the mock server (a real client never sends output frames).
  const payload = toBytes(data);
  const out = new Uint8Array(13 + payload.length);
  const dv = new DataView(out.buffer);
  out[0] = FRAME_OUTPUT;
  dv.setUint32(1, streamId >>> 0, false);
  dv.setBigUint64(5, BigInt(offset), false);
  out.set(payload, 13);
  return out;
}

/** Returns {kind:'output',stream,offset,payload} | {kind:'input',stream,payload} | null (malformed/unknown). */
export function decodeBinaryFrame(buf) {
  const bytes = toBytes(buf);
  if (bytes.length < 5) return null;
  const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const stream = dv.getUint32(1, false);
  if (bytes[0] === FRAME_OUTPUT) {
    if (bytes.length < 13) return null;
    const offset = Number(dv.getBigUint64(5, false));
    return { kind: 'output', stream, offset, payload: bytes.subarray(13) };
  }
  if (bytes[0] === FRAME_INPUT) {
    return { kind: 'input', stream, payload: bytes.subarray(5) };
  }
  return null;
}

/** Parse a JSON control frame; returns null if not an object with a string `t`. */
export function parseControl(text) {
  let msg;
  try {
    msg = JSON.parse(text);
  } catch {
    return null;
  }
  if (!msg || typeof msg !== 'object' || typeof msg.t !== 'string') return null;
  return msg;
}

// ---------------------------------------------------------------------------------------------
// Pairing URL fragment
// ---------------------------------------------------------------------------------------------

const SECRET_RE = /^[A-Za-z0-9_-]{16,128}$/;
const HOST_RE = /^(\[[0-9a-fA-F:.]+\]|[0-9a-fA-F:.]+|[A-Za-z0-9.-]+)$/;

/**
 * Parse `#v=1&s=..&fp=..&h=a,b&id=..&exp=..&n=..`.
 * Returns {ok:true, secret, fp, hosts, id, exp, name, expiredHint} or {ok:false, reason}.
 * `expiredHint` is advisory only (phone clocks drift); the server is the authority.
 */
export function parsePairFragment(hash, nowSec = Math.floor(Date.now() / 1000)) {
  const raw = String(hash || '').replace(/^#/, '');
  if (!raw) return { ok: false, reason: 'missing' };
  let p;
  try {
    p = new URLSearchParams(raw);
  } catch {
    return { ok: false, reason: 'malformed' };
  }
  const v = p.get('v');
  if (v !== null && v !== String(PROTOCOL_VERSION)) return { ok: false, reason: 'bad_version' };
  const secret = p.get('s');
  if (!secret) return { ok: false, reason: 'missing_secret' };
  if (!SECRET_RE.test(secret)) return { ok: false, reason: 'bad_secret' };
  const hosts = (p.get('h') || '')
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s && HOST_RE.test(s));
  const expN = Number(p.get('exp'));
  const exp = Number.isFinite(expN) && expN > 0 ? expN : null;
  return {
    ok: true,
    secret,
    fp: p.get('fp') || '',
    hosts,
    id: (p.get('id') || '').slice(0, 128),
    exp,
    name: (p.get('n') || '').slice(0, 128),
    expiredHint: exp !== null && nowSec > exp,
  };
}

/** base64url SHA-256 -> "ab12 cd34 ..." (lowercase hex, groups of 4). Returns '' if undecodable. */
export function fingerprintToGroups(b64url) {
  if (!b64url || !/^[A-Za-z0-9_-]+$/.test(b64url)) return '';
  try {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - (b64.length % 4)) % 4));
    let hex = '';
    for (let i = 0; i < bin.length; i++) hex += bin.charCodeAt(i).toString(16).padStart(2, '0');
    return hex.match(/.{1,4}/g).join(' ');
  } catch {
    return '';
  }
}

// ---------------------------------------------------------------------------------------------
// Backoff
// ---------------------------------------------------------------------------------------------

/** attempt is 0-based. Exponential 0.5s,1s,2s... capped at max, +/- jitter fraction. */
export function backoffDelay(attempt, { base = 500, max = 30000, jitter = 0.2, random = Math.random } = {}) {
  const raw = Math.min(max, base * 2 ** Math.min(attempt, 30));
  const j = 1 + (random() * 2 - 1) * jitter;
  return Math.max(0, Math.round(raw * j));
}

// ---------------------------------------------------------------------------------------------
// Pairing flow
// ---------------------------------------------------------------------------------------------

const defaultSleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function readJson(res) {
  try {
    return await res.json();
  } catch {
    return {};
  }
}

/**
 * POST /v1/pair, then (if pending) long-poll GET /v1/pair/<id>.
 * Resolves (never rejects) with one of:
 *   {status:'approved', token, deviceId}
 *   {status:'denied'} | {status:'expired'}
 *   {status:'invalid'}                       (401: wrong/expired/consumed secret)
 *   {status:'locked', retryAfter}            (429)
 *   {status:'cancelled'}                     (signal aborted)
 *   {status:'error', message}                (network/protocol failure)
 * `onState('posting'|'pending')` is called as the flow advances.
 */
export async function pairDevice({
  fetch: fetchFn,
  base = '',
  secret,
  deviceName,
  platform = 'web',
  onState = () => {},
  signal,
  sleep = defaultSleep,
  now = () => Date.now(),
  overallTimeoutMs = 5 * 60 * 1000,
  maxPollErrors = 3,
}) {
  const aborted = () => signal && signal.aborted;
  const init = (extra) => ({
    credentials: 'omit',
    cache: 'no-store',
    referrerPolicy: 'no-referrer',
    signal,
    ...extra,
  });
  const started = now();
  try {
    onState('posting');
    const res = await fetchFn(
      `${base}/v1/pair`,
      init({
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ v: PROTOCOL_VERSION, secret, device_name: deviceName, platform }),
      }),
    );
    let body = await readJson(res);
    if (res.status === 429) return { status: 'locked', retryAfter: Number(body.retry_after) || 30 };
    if (res.status === 401) return { status: 'invalid' };
    if (!res.ok) return { status: 'error', message: `HTTP ${res.status}` };

    let errors = 0;
    for (;;) {
      if (aborted()) return { status: 'cancelled' };
      if (body.status === 'approved') {
        if (typeof body.token !== 'string' || !body.token) return { status: 'error', message: 'approved without token' };
        return { status: 'approved', token: body.token, deviceId: String(body.device_id || '') };
      }
      if (body.status === 'denied') return { status: 'denied' };
      if (body.status === 'expired') return { status: 'expired' };
      if (body.status !== 'pending' || typeof body.poll !== 'string') {
        return { status: 'error', message: 'unexpected pairing response' };
      }
      onState('pending');
      const pollId = body.poll;
      for (;;) {
        if (aborted()) return { status: 'cancelled' };
        if (now() - started > overallTimeoutMs) return { status: 'expired' };
        try {
          const r = await fetchFn(`${base}/v1/pair/${encodeURIComponent(pollId)}`, init({ method: 'GET' }));
          if (r.status === 404 || r.status === 410) return { status: 'expired' };
          if (r.status === 429) return { status: 'locked', retryAfter: Number((await readJson(r)).retry_after) || 30 };
          if (r.status === 401) return { status: 'invalid' };
          if (!r.ok) throw new Error(`HTTP ${r.status}`);
          body = await readJson(r);
          errors = 0;
          if (body.status === 'pending') {
            await sleep(250); // long-poll normally blocks ~25 s; this just prevents a hot loop
            continue;
          }
          break; // approved/denied/expired handled at the top of the outer loop
        } catch (e) {
          if (aborted()) return { status: 'cancelled' };
          if (++errors > maxPollErrors) return { status: 'error', message: String((e && e.message) || e) };
          await sleep(backoffDelay(errors));
        }
      }
    }
  } catch (e) {
    if (aborted()) return { status: 'cancelled' };
    return { status: 'error', message: String((e && e.message) || e) };
  }
}

/** POST /v1/revoke (Bearer): the device unpairs itself. Returns true on 2xx. */
export async function revokeSelf({ fetch: fetchFn, base = '', token }) {
  try {
    const res = await fetchFn(`${base}/v1/revoke`, {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: '{}',
    });
    return res.ok;
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// RemoteClient: authenticated WebSocket session with reconnect + replay
// ---------------------------------------------------------------------------------------------

const FATAL_CODES = new Set([CLOSE.BAD_REQUEST, CLOSE.AUTH, CLOSE.KILLED]);

/**
 * Events (use .on(name, fn)):
 *  state {state, attempt?, delay?, code?}  state in connecting|authenticating|ready|reconnecting|stopped|fatal
 *  welcome, tree, snapshot, output {bytes, offset}, pane_state, pane_closed, session_killed, error,
 *  latency {ms}, fatal {code, reason}
 */
export class RemoteClient {
  constructor({
    url,
    token,
    WebSocketImpl = globalThis.WebSocket,
    timers = { setTimeout: (f, m) => setTimeout(f, m), clearTimeout: (i) => clearTimeout(i), now: () => Date.now() },
    random = Math.random,
    clientName = 'web',
    streamId = 1,
    pingIntervalMs = 15000,
    silenceTimeoutMs = 45000,
    helloTimeoutMs = 5000,
    backoff = {},
  }) {
    this.url = url;
    this.token = token;
    this.WS = WebSocketImpl;
    this.t = timers;
    this.random = random;
    this.clientName = clientName;
    this.stream = streamId;
    this.pingIntervalMs = pingIntervalMs;
    this.silenceTimeoutMs = silenceTimeoutMs;
    this.helloTimeoutMs = helloTimeoutMs;
    this.backoffOpts = backoff;

    this.handlers = new Map();
    this.ws = null;
    this.stopped = true;
    this.ready = false;
    this.attempt = 0;
    this.paneId = null; // pane we want attached (re-attached after reconnect)
    this.awaitingSnapshot = false;
    this.lastOffset = 0;
    this.sinceAck = 0;
    this.nextActionId = 1;
    this.pendingActions = new Map();
    this.pingN = 0;
    this.pingSent = new Map();
    this.timerIds = { reconnect: null, hello: null, ping: null, watchdog: null };
    this.lastRx = 0;
  }

  on(name, fn) {
    if (!this.handlers.has(name)) this.handlers.set(name, []);
    this.handlers.get(name).push(fn);
    return this;
  }

  _emit(name, payload) {
    for (const fn of this.handlers.get(name) || []) {
      try {
        fn(payload);
      } catch (e) {
        // A UI handler bug must not kill the transport.
        if (typeof console !== 'undefined') console.error('handler error', name, e);
      }
    }
  }

  start() {
    this.stopped = false;
    this.attempt = 0;
    this._connect();
  }

  /** User-initiated disconnect: closes and does not reconnect. */
  stop() {
    this.stopped = true;
    this._clearTimers();
    this._dropSocket(1000, 'client stop');
    this._rejectActions('stopped');
    this._emit('state', { state: 'stopped' });
  }

  /** Reconnect immediately (page became visible / network back / user button). */
  reconnectNow() {
    if (this.stopped) {
      this.start();
      return;
    }
    if (this.ready) return;
    this._clearTimers();
    this._dropSocket(1000, 'reconnect');
    this._connect();
  }

  _clearTimers() {
    for (const k of Object.keys(this.timerIds)) {
      if (this.timerIds[k] !== null) {
        this.t.clearTimeout(this.timerIds[k]);
        this.timerIds[k] = null;
      }
    }
  }

  _dropSocket(code, reason) {
    const ws = this.ws;
    this.ws = null;
    this.ready = false;
    if (ws) {
      ws.onopen = ws.onmessage = ws.onclose = ws.onerror = null;
      try {
        ws.close(code, reason);
      } catch {
        /* already closed */
      }
    }
  }

  _connect() {
    this._emit('state', { state: this.attempt === 0 ? 'connecting' : 'reconnecting', attempt: this.attempt });
    let ws;
    try {
      ws = new this.WS(this.url, SUBPROTOCOL);
    } catch (e) {
      this._scheduleReconnect(0);
      return;
    }
    ws.binaryType = 'arraybuffer';
    this.ws = ws;
    this.lastRx = this.t.now();
    ws.onopen = () => {
      if (this.ws !== ws) return;
      this._emit('state', { state: 'authenticating' });
      // hello MUST be the first frame, within 3 s of connect.
      this._sendJson({ t: 'hello', v: PROTOCOL_VERSION, token: this.token, client: this.clientName, caps: ['binary', 'resnap'] });
      this.timerIds.hello = this.t.setTimeout(() => {
        this.timerIds.hello = null;
        this._onClosed(4000, 'hello timeout');
      }, this.helloTimeoutMs);
    };
    ws.onmessage = (ev) => {
      if (this.ws !== ws) return;
      this.lastRx = this.t.now();
      if (typeof ev.data === 'string') this._onControl(ev.data);
      else this._onBinary(ev.data);
    };
    ws.onclose = (ev) => {
      if (this.ws !== ws) return;
      this._onClosed(ev && ev.code, ev && ev.reason);
    };
    ws.onerror = () => {
      /* followed by onclose; nothing to do */
    };
  }

  _onClosed(code, reason) {
    this._clearTimers();
    this._dropSocket(1000, 'closing');
    this.ready = false;
    this._rejectActions('connection closed');
    if (this.stopped) return;
    if (FATAL_CODES.has(code)) {
      this.stopped = true;
      this._emit('state', { state: 'fatal', code });
      this._emit('fatal', { code, reason: reason || '' });
      return;
    }
    const minDelay = code === CLOSE.RATE_LIMITED ? 30000 : 0;
    this._scheduleReconnect(minDelay, code);
  }

  _scheduleReconnect(minDelay, code) {
    const delay = Math.max(minDelay, backoffDelay(this.attempt, { ...this.backoffOpts, random: this.random }));
    this.attempt += 1;
    this._emit('state', { state: 'reconnecting', attempt: this.attempt, delay, code });
    this.timerIds.reconnect = this.t.setTimeout(() => {
      this.timerIds.reconnect = null;
      this._connect();
    }, delay);
  }

  _sendJson(obj) {
    if (!this.ws || this.ws.readyState !== 1) return false;
    this.ws.send(JSON.stringify(obj));
    return true;
  }

  _onControl(text) {
    const msg = parseControl(text);
    if (!msg) return;
    switch (msg.t) {
      case 'welcome':
        if (this.timerIds.hello !== null) this.t.clearTimeout(this.timerIds.hello);
        this.timerIds.hello = null;
        this.ready = true;
        this.attempt = 0;
        this._emit('state', { state: 'ready' });
        this._emit('welcome', msg);
        this._sendJson({ t: 'list' });
        if (this.paneId !== null) this._sendAttach(); // replay after reconnect
        this._startHeartbeat();
        break;
      case 'tree':
        this._emit('tree', msg);
        break;
      case 'tree_changed':
        this._sendJson({ t: 'list' });
        break;
      case 'snapshot':
        this.awaitingSnapshot = false;
        this.lastOffset = Number(msg.offset) || 0;
        this.sinceAck = 0;
        this._emit('snapshot', msg);
        break;
      case 'pane_state':
        this._emit('pane_state', msg);
        break;
      case 'pane_closed':
        if (msg.pane === this.paneId) {
          this.paneId = null;
          this.awaitingSnapshot = false;
        }
        this._emit('pane_closed', msg);
        break;
      case 'session_killed':
        this._emit('session_killed', msg); // server closes with 4403 right after
        break;
      case 'result': {
        const p = this.pendingActions.get(msg.id);
        if (p) {
          this.pendingActions.delete(msg.id);
          p.resolve(msg);
        }
        break;
      }
      case 'pong': {
        const sent = this.pingSent.get(msg.n);
        if (sent !== undefined) {
          this.pingSent.delete(msg.n);
          this._emit('latency', { ms: this.t.now() - sent });
        }
        break;
      }
      case 'error':
        this._emit('error', msg);
        break;
      default:
        break; // unknown types are ignored (forward compatibility)
    }
  }

  _onBinary(data) {
    const f = decodeBinaryFrame(data);
    if (!f || f.kind !== 'output' || f.stream !== this.stream) return;
    if (this.awaitingSnapshot) return; // stale frames from a previously attached pane
    this.lastOffset = f.offset + f.payload.length;
    this.sinceAck += f.payload.length;
    this._emit('output', { bytes: f.payload, offset: f.offset });
    if (this.sinceAck >= ACK_EVERY) {
      this.sinceAck = 0;
      this._sendJson({ t: 'ack', stream: this.stream, offset: this.lastOffset });
    }
  }

  _startHeartbeat() {
    const tick = () => {
      this.timerIds.ping = null;
      if (!this.ready) return;
      const n = ++this.pingN;
      this.pingSent.set(n, this.t.now());
      if (this.pingSent.size > 8) this.pingSent.delete(this.pingSent.keys().next().value);
      this._sendJson({ t: 'ping', n });
      this.timerIds.ping = this.t.setTimeout(tick, this.pingIntervalMs);
    };
    const watch = () => {
      this.timerIds.watchdog = null;
      if (!this.ready) return;
      if (this.t.now() - this.lastRx > this.silenceTimeoutMs) {
        this._onClosed(4000, 'silence');
        return;
      }
      this.timerIds.watchdog = this.t.setTimeout(watch, 5000);
    };
    tick();
    this.timerIds.watchdog = this.t.setTimeout(watch, 5000);
  }

  _rejectActions(reason) {
    for (const p of this.pendingActions.values()) p.resolve({ t: 'result', ok: false, error: { code: 'disconnected', message: reason } });
    this.pendingActions.clear();
  }

  // ---- public commands ----

  list() {
    return this._sendJson({ t: 'list' });
  }

  _sendAttach() {
    this.awaitingSnapshot = true;
    this._sendJson({ t: 'attach', pane: this.paneId, stream: this.stream, replay: true });
  }

  /** Attach to a pane (detaching the previous one). */
  attach(paneId) {
    if (this.paneId !== null && this.ready) this._sendJson({ t: 'detach', stream: this.stream });
    this.paneId = paneId;
    if (this.ready) this._sendAttach();
  }

  detach() {
    if (this.paneId !== null && this.ready) this._sendJson({ t: 'detach', stream: this.stream });
    this.paneId = null;
    this.awaitingSnapshot = false;
  }

  /** Send raw input bytes (string is UTF-8 encoded). Returns false if not connected. */
  sendInput(data) {
    if (!this.ready || this.paneId === null || !this.ws) return false;
    const bytes = toBytes(data);
    for (let i = 0; i < bytes.length; i += MAX_INPUT_PAYLOAD) {
      this.ws.send(encodeInputFrame(this.stream, bytes.subarray(i, i + MAX_INPUT_PAYLOAD)));
    }
    return true;
  }

  sendResize(cols, rows) {
    return this._sendJson({ t: 'resize', stream: this.stream, cols, rows });
  }

  /** Returns Promise<{ok, data?, error?}>. */
  action(name, target = {}, params = {}) {
    const id = this.nextActionId++;
    return new Promise((resolve) => {
      if (!this._sendJson({ t: 'action', id, name, target, params })) {
        resolve({ t: 'result', id, ok: false, error: { code: 'disconnected', message: 'not connected' } });
        return;
      }
      this.pendingActions.set(id, { resolve });
    });
  }
}
