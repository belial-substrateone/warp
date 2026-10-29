import test from 'node:test';
import assert from 'node:assert/strict';
import {
  encodeInputFrame, encodeOutputFrame, decodeBinaryFrame, parseControl, parsePairFragment, fingerprintToGroups,
  backoffDelay, pairDevice, revokeSelf, RemoteClient, CLOSE, SUBPROTOCOL, ACK_EVERY, MAX_INPUT_PAYLOAD,
} from '../js/protocol.js';
import { FakeClock, FakeWS, jsonResponse } from './helpers.mjs';

// ------------------------------------------------------------------ frames
test('input frame layout', () => {
  const f = encodeInputFrame(1, 'ab');
  assert.deepEqual([...f], [0x02, 0, 0, 0, 1, 0x61, 0x62]);
  const d = decodeBinaryFrame(f);
  assert.equal(d.kind, 'input');
  assert.equal(d.stream, 1);
  assert.deepEqual([...d.payload], [0x61, 0x62]);
});

test('output frame round trip incl. big offset and subarray views', () => {
  const off = 2 ** 40 + 5;
  const f = encodeOutputFrame(0xdeadbeef, off, new Uint8Array([1, 2, 3]));
  assert.equal(f.length, 13 + 3);
  assert.deepEqual([...f.subarray(0, 5)], [0x01, 0xde, 0xad, 0xbe, 0xef]);
  const d = decodeBinaryFrame(f.buffer);
  assert.equal(d.kind, 'output');
  assert.equal(d.stream, 0xdeadbeef);
  assert.equal(d.offset, off);
  assert.deepEqual([...d.payload], [1, 2, 3]);
  // view into a larger buffer
  const big = new Uint8Array(40); big.set(f, 7);
  assert.equal(decodeBinaryFrame(big.subarray(7, 7 + f.length)).offset, off);
});

test('malformed / unknown binary frames return null', () => {
  assert.equal(decodeBinaryFrame(new Uint8Array([1, 0, 0])), null);
  assert.equal(decodeBinaryFrame(new Uint8Array([1, 0, 0, 0, 1, 0, 0])), null); // output too short
  assert.equal(decodeBinaryFrame(new Uint8Array([9, 0, 0, 0, 1, 5])), null);
  assert.equal(decodeBinaryFrame(new Uint8Array(0)), null);
});

test('parseControl', () => {
  assert.deepEqual(parseControl('{"t":"pong","n":3}'), { t: 'pong', n: 3 });
  assert.equal(parseControl('nope'), null);
  assert.equal(parseControl('[]'), null);
  assert.equal(parseControl('{"x":1}'), null);
  assert.equal(parseControl('null'), null);
});

// ------------------------------------------------------------------ pair fragment
const SECRET = 'A'.repeat(43);
test('parsePairFragment happy path', () => {
  const r = parsePairFragment(`#v=1&s=${SECRET}&fp=qrs&h=10.0.0.5,100.64.0.1,[fd7a::1]&id=abc&exp=2000&n=My%20PC`, 1000);
  assert.equal(r.ok, true);
  assert.equal(r.secret, SECRET);
  assert.deepEqual(r.hosts, ['10.0.0.5', '100.64.0.1', '[fd7a::1]']);
  assert.equal(r.name, 'My PC');
  assert.equal(r.expiredHint, false);
  assert.equal(parsePairFragment(`#s=${SECRET}&exp=999`, 1000).expiredHint, true);
});

test('parsePairFragment rejects bad input and drops hostile hosts', () => {
  assert.equal(parsePairFragment('').reason, 'missing');
  assert.equal(parsePairFragment('#v=1').reason, 'missing_secret');
  assert.equal(parsePairFragment('#v=2&s=' + SECRET).reason, 'bad_version');
  assert.equal(parsePairFragment('#s=short').reason, 'bad_secret');
  assert.equal(parsePairFragment('#s=' + 'a/b'.repeat(10)).reason, 'bad_secret');
  const r = parsePairFragment(`#s=${SECRET}&h=1.2.3.4,evil.com/x%3Fy,"><script>`);
  assert.deepEqual(r.hosts, ['1.2.3.4']);
});

test('fingerprintToGroups', () => {
  // sha256 of empty = e3b0c442 98fc1c14 ...
  const b64u = '47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU';
  assert.equal(fingerprintToGroups(b64u).startsWith('e3b0 c442 98fc 1c14'), true);
  assert.equal(fingerprintToGroups('!!'), '');
  assert.equal(fingerprintToGroups(''), '');
});

// ------------------------------------------------------------------ backoff
test('backoffDelay grows exponentially, caps, and jitters within bounds', () => {
  const noJ = { jitter: 0 };
  assert.deepEqual([0, 1, 2, 3, 4].map((a) => backoffDelay(a, noJ)), [500, 1000, 2000, 4000, 8000]);
  assert.equal(backoffDelay(20, noJ), 30000);
  assert.equal(backoffDelay(1000, noJ), 30000);
  assert.equal(backoffDelay(2, { random: () => 0 }), Math.round(2000 * 0.8));
  assert.equal(backoffDelay(2, { random: () => 1 }), Math.round(2000 * 1.2));
});

// ------------------------------------------------------------------ pairing flow
function scriptedFetch(responses) {
  const calls = [];
  const f = async (url, init) => {
    calls.push({ url, init });
    const r = responses.shift();
    if (!r) throw new Error('unexpected fetch ' + url);
    if (r instanceof Error) throw r;
    return r;
  };
  f.calls = calls;
  return f;
}
const noSleep = async () => {};

test('pair: pending -> approved, request shape', async () => {
  const states = [];
  const fetch = scriptedFetch([
    jsonResponse(200, { status: 'pending', poll: 'p/1' }),
    jsonResponse(200, { status: 'pending' }),
    jsonResponse(200, { status: 'approved', device_id: 'dev1', token: 'TOK' }),
  ]);
  const r = await pairDevice({ fetch, secret: SECRET, deviceName: 'Web (Test)', onState: (s) => states.push(s), sleep: noSleep });
  assert.deepEqual(r, { status: 'approved', token: 'TOK', deviceId: 'dev1' });
  assert.deepEqual(states, ['posting', 'pending']);
  const [post, poll1] = fetch.calls;
  assert.equal(post.url, '/v1/pair');
  assert.equal(post.init.method, 'POST');
  assert.equal(post.init.credentials, 'omit');
  assert.equal(post.init.headers['content-type'], 'application/json');
  assert.deepEqual(JSON.parse(post.init.body), { v: 1, secret: SECRET, device_name: 'Web (Test)', platform: 'web' });
  assert.equal(poll1.url, '/v1/pair/p%2F1'); // poll id is encoded
});

test('pair: direct approval (approval disabled)', async () => {
  const fetch = scriptedFetch([jsonResponse(200, { status: 'approved', device_id: 'd', token: 'T' })]);
  assert.equal((await pairDevice({ fetch, secret: SECRET, deviceName: 'x', sleep: noSleep })).status, 'approved');
});

test('pair: denied / expired / invalid / locked', async () => {
  const run = (...resp) => pairDevice({ fetch: scriptedFetch(resp), secret: SECRET, deviceName: 'x', sleep: noSleep });
  assert.equal((await run(jsonResponse(200, { status: 'pending', poll: 'a' }), jsonResponse(200, { status: 'denied' }))).status, 'denied');
  assert.equal((await run(jsonResponse(200, { status: 'pending', poll: 'a' }), jsonResponse(200, { status: 'expired' }))).status, 'expired');
  assert.equal((await run(jsonResponse(200, { status: 'pending', poll: 'a' }), jsonResponse(404, {}))).status, 'expired');
  assert.equal((await run(jsonResponse(401, {}))).status, 'invalid');
  assert.deepEqual(await run(jsonResponse(429, { retry_after: 60 })), { status: 'locked', retryAfter: 60 });
  assert.equal((await run(jsonResponse(500, {}))).status, 'error');
  assert.equal((await run(jsonResponse(200, { status: 'approved' }))).status, 'error'); // no token
  assert.equal((await run(jsonResponse(200, { status: 'weird' }))).status, 'error');
});

test('pair: network error on POST and transient poll errors', async () => {
  assert.equal((await pairDevice({ fetch: scriptedFetch([new Error('boom')]), secret: SECRET, deviceName: 'x', sleep: noSleep })).status, 'error');
  const ok = await pairDevice({
    fetch: scriptedFetch([
      jsonResponse(200, { status: 'pending', poll: 'a' }),
      new Error('blip'),
      jsonResponse(502, {}),
      jsonResponse(200, { status: 'approved', device_id: 'd', token: 'T' }),
    ]),
    secret: SECRET, deviceName: 'x', sleep: noSleep,
  });
  assert.equal(ok.status, 'approved');
  const bad = await pairDevice({
    fetch: scriptedFetch([jsonResponse(200, { status: 'pending', poll: 'a' }), new Error('1'), new Error('2'), new Error('3'), new Error('4')]),
    secret: SECRET, deviceName: 'x', sleep: noSleep,
  });
  assert.equal(bad.status, 'error');
});

test('pair: abort and overall timeout', async () => {
  const ac = new AbortController();
  const fetch = scriptedFetch([jsonResponse(200, { status: 'pending', poll: 'a' })]);
  const r = await pairDevice({ fetch, secret: SECRET, deviceName: 'x', sleep: noSleep, signal: ac.signal, onState: (s) => { if (s === 'pending') ac.abort(); } });
  assert.equal(r.status, 'cancelled');
  let t = 0;
  const r2 = await pairDevice({
    fetch: scriptedFetch([jsonResponse(200, { status: 'pending', poll: 'a' })]), secret: SECRET, deviceName: 'x', sleep: noSleep,
    now: () => (t += 400000), overallTimeoutMs: 300000,
  });
  assert.equal(r2.status, 'expired');
});

test('revokeSelf sends bearer', async () => {
  const f = scriptedFetch([jsonResponse(200, {})]);
  assert.equal(await revokeSelf({ fetch: f, token: 'TOK' }), true);
  assert.equal(f.calls[0].url, '/v1/revoke');
  assert.equal(f.calls[0].init.headers.authorization, 'Bearer TOK');
  assert.equal(await revokeSelf({ fetch: scriptedFetch([new Error('x')]), token: 't' }), false);
});

// ------------------------------------------------------------------ RemoteClient
function mk(opts = {}) {
  FakeWS.reset();
  const clock = new FakeClock();
  const c = new RemoteClient({ url: 'wss://h/v1/ws', token: 'TOK', WebSocketImpl: FakeWS, timers: clock.api(), random: () => 0.5, ...opts });
  const events = [];
  for (const n of ['state', 'welcome', 'tree', 'snapshot', 'output', 'pane_state', 'pane_closed', 'session_killed', 'error', 'latency', 'fatal']) {
    c.on(n, (p) => events.push([n, p]));
  }
  return { c, clock, events, ws: () => FakeWS.instances.at(-1) };
}
const welcome = { t: 'welcome', v: 1, device: 'd', server: 'anonwarp 1', limits: {}, phone_resize: false };
const states = (events) => events.filter((e) => e[0] === 'state').map((e) => e[1].state);

test('client: hello is first frame, then list on welcome', () => {
  const { c, ws, events } = mk();
  c.start();
  assert.equal(ws().protocol, SUBPROTOCOL);
  assert.equal(ws().binaryType, 'arraybuffer');
  ws().open();
  assert.deepEqual(ws().sentJson(), [{ t: 'hello', v: 1, token: 'TOK', client: 'web', caps: ['binary', 'resnap'] }]);
  ws().recvJson(welcome);
  assert.equal(ws().sentJson()[1].t, 'list');
  assert.deepEqual(states(events), ['connecting', 'authenticating', 'ready']);
});

test('client: attach, snapshot gating, output, input framing and chunking', () => {
  const { c, ws, events } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  c.attach('pane:1');
  assert.deepEqual(ws().sentJson().at(-1), { t: 'attach', pane: 'pane:1', stream: 1, replay: true });
  // output before snapshot is dropped
  ws().recv(encodeOutputFrame(1, 0, 'stale').buffer);
  assert.equal(events.filter((e) => e[0] === 'output').length, 0);
  ws().recvJson({ t: 'snapshot', pane: 'pane:1', cols: 80, rows: 24, alt_screen: false, offset: 100 });
  ws().recv(encodeOutputFrame(1, 100, 'hi').buffer);
  const out = events.find((e) => e[0] === 'output')[1];
  assert.equal(new TextDecoder().decode(out.bytes), 'hi');
  assert.equal(out.offset, 100);
  // other stream ignored
  ws().recv(encodeOutputFrame(7, 102, 'x').buffer);
  assert.equal(events.filter((e) => e[0] === 'output').length, 1);

  assert.equal(c.sendInput('ls\r'), true);
  const f = decodeBinaryFrame(ws().sentBinary()[0]);
  assert.equal(f.kind, 'input'); assert.equal(f.stream, 1);
  assert.equal(new TextDecoder().decode(f.payload), 'ls\r');

  c.sendInput(new Uint8Array(MAX_INPUT_PAYLOAD * 2 + 10));
  const sizes = ws().sentBinary().slice(1).map((b) => b.length - 5);
  assert.deepEqual(sizes, [MAX_INPUT_PAYLOAD, MAX_INPUT_PAYLOAD, 10]);
});

test('client: acks every 256 KiB', () => {
  const { c, ws } = mk();
  c.start(); ws().open(); ws().recvJson(welcome); c.attach('p');
  ws().recvJson({ t: 'snapshot', cols: 80, rows: 24, offset: 0 });
  const chunk = new Uint8Array(ACK_EVERY / 2);
  ws().recv(encodeOutputFrame(1, 0, chunk).buffer);
  assert.equal(ws().sentJson().filter((m) => m.t === 'ack').length, 0);
  ws().recv(encodeOutputFrame(1, chunk.length, chunk).buffer);
  const acks = ws().sentJson().filter((m) => m.t === 'ack');
  assert.deepEqual(acks, [{ t: 'ack', stream: 1, offset: ACK_EVERY }]);
});

test('client: sendInput refused when not ready or no pane', () => {
  const { c, ws } = mk();
  assert.equal(c.sendInput('x'), false);
  c.start(); ws().open();
  assert.equal(c.sendInput('x'), false);
  ws().recvJson(welcome);
  assert.equal(c.sendInput('x'), false); // no pane
});

test('client: switching pane = detach + attach', () => {
  const { c, ws } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  c.attach('a'); c.attach('b');
  const tail = ws().sentJson().slice(-3).map((m) => m.t + (m.pane || ''));
  assert.deepEqual(tail, ['attacha', 'detach', 'attachb']);
});

test('client: tree_changed triggers list; unknown types ignored; error forwarded', () => {
  const { c, ws, events } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  const n = ws().sentJson().length;
  ws().recvJson({ t: 'tree_changed' });
  assert.equal(ws().sentJson().length, n + 1);
  ws().recvJson({ t: 'from_the_future', x: 1 });
  ws().recvJson({ t: 'error', code: 'resize_denied', message: 'no' });
  assert.equal(events.find((e) => e[0] === 'error')[1].code, 'resize_denied');
  ws().recvJson({ t: 'tree', windows: [] });
  assert.equal(events.filter((e) => e[0] === 'tree').length, 1);
});

test('client: reconnect with backoff, hello again, replay re-attach', () => {
  const { c, ws, clock, events } = mk();
  c.start(); ws().open(); ws().recvJson(welcome); c.attach('p1');
  ws().serverClose(1006);
  assert.deepEqual(states(events).slice(-1), ['reconnecting']);
  const first = events.filter((e) => e[0] === 'state' && e[1].delay !== undefined).at(-1)[1];
  assert.equal(first.attempt, 1);
  assert.equal(first.delay, 500); // random()=0.5 -> no jitter
  assert.equal(FakeWS.instances.length, 1);
  clock.advance(499); assert.equal(FakeWS.instances.length, 1);
  clock.advance(1); assert.equal(FakeWS.instances.length, 2);
  // second failure before welcome -> longer delay
  ws().open(); ws().serverClose(1006);
  const second = events.filter((e) => e[0] === 'state' && e[1].delay !== undefined).at(-1)[1];
  assert.equal(second.delay, 1000);
  clock.advance(1000);
  assert.equal(FakeWS.instances.length, 3);
  ws().open(); ws().recvJson(welcome);
  assert.equal(ws().sentJson()[0].t, 'hello');
  const t = ws().sentJson().map((m) => m.t);
  assert.deepEqual(t.filter((x) => x !== 'ping'), ['hello', 'list', 'attach']);
  assert.equal(ws().sentJson().find((m) => m.t === 'attach').replay, true);
  // attempt counter reset after success
  ws().serverClose(1006);
  assert.equal(events.filter((e) => e[0] === 'state' && e[1].delay !== undefined).at(-1)[1].delay, 500);
});

test('client: fatal close codes do not reconnect', () => {
  for (const code of [CLOSE.KILLED, CLOSE.AUTH, CLOSE.BAD_REQUEST]) {
    const { c, ws, clock, events } = mk();
    c.start(); ws().open(); ws().recvJson(welcome);
    ws().serverClose(code, 'why');
    assert.equal(clock.pending, 0);
    assert.equal(FakeWS.instances.length, 1);
    const fatal = events.find((e) => e[0] === 'fatal')[1];
    assert.deepEqual(fatal, { code, reason: 'why' });
    assert.equal(states(events).at(-1), 'fatal');
  }
});

test('client: 4429 waits at least 30 s; 4408 idle reconnects', () => {
  let m = mk();
  m.c.start(); m.ws().open(); m.ws().recvJson(welcome);
  m.ws().serverClose(CLOSE.RATE_LIMITED);
  assert.equal(m.events.filter((e) => e[0] === 'state' && e[1].delay !== undefined).at(-1)[1].delay, 30000);
  m = mk();
  m.c.start(); m.ws().open(); m.ws().recvJson(welcome);
  m.ws().serverClose(CLOSE.IDLE);
  m.clock.advance(600);
  assert.equal(FakeWS.instances.length, 2);
});

test('client: hello timeout and silence watchdog force reconnect', () => {
  const m = mk();
  m.c.start(); m.ws().open();
  m.clock.advance(5000); // no welcome
  assert.equal(FakeWS.instances[0].closed.code, 1000);
  m.clock.advance(1000);
  assert.equal(FakeWS.instances.length, 2);

  const s = mk({ pingIntervalMs: 15000, silenceTimeoutMs: 45000 });
  s.c.start(); s.ws().open(); s.ws().recvJson(welcome);
  // keep alive with pongs every 10s for a minute: no reconnect
  for (let i = 0; i < 6; i++) { s.clock.advance(10000); s.ws().recvJson({ t: 'pong', n: 0 }); }
  assert.equal(FakeWS.instances.length, 1);
  s.clock.advance(50000); // silence
  s.clock.advance(1000);
  assert.equal(FakeWS.instances.length, 2);
});

test('client: ping/pong latency', () => {
  const { c, ws, clock, events } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  const ping = ws().sentJson().find((m) => m.t === 'ping');
  assert.ok(ping);
  clock.advance(42);
  ws().recvJson({ t: 'pong', n: ping.n });
  assert.equal(events.find((e) => e[0] === 'latency')[1].ms, 42);
  clock.advance(15000);
  assert.equal(ws().sentJson().filter((m) => m.t === 'ping').length, 2);
});

test('client: action request/result matching and failure on disconnect', async () => {
  const { c, ws } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  const p = c.action('tab.create', {}, {});
  const sent = ws().sentJson().find((m) => m.t === 'action');
  assert.equal(sent.name, 'tab.create');
  ws().recvJson({ t: 'result', id: sent.id, ok: true, data: {} });
  assert.equal((await p).ok, true);
  const p2 = c.action('pane.close', { pane: 'x' });
  ws().serverClose(1006);
  const r = await p2;
  assert.equal(r.ok, false); assert.equal(r.error.code, 'disconnected');
  assert.equal((await c.action('x')).ok, false); // not connected
});

test('client: stop() closes and never reconnects; reconnectNow restarts', () => {
  const m = mk();
  m.c.start(); m.ws().open(); m.ws().recvJson(welcome);
  m.c.stop();
  assert.equal(m.clock.pending, 0);
  assert.equal(FakeWS.instances[0].closed.code, 1000);
  m.c.reconnectNow();
  assert.equal(FakeWS.instances.length, 2);
});

test('client: pane_closed for attached pane clears it so reconnect will not re-attach', () => {
  const { c, ws, clock } = mk();
  c.start(); ws().open(); ws().recvJson(welcome); c.attach('p');
  ws().recvJson({ t: 'pane_closed', pane: 'p' });
  ws().serverClose(1006); clock.advance(600); ws().open(); ws().recvJson(welcome);
  assert.equal(ws().sentJson().some((m) => m.t === 'attach'), false);
});

test('client: pane_state and session_killed are forwarded', () => {
  const { c, ws, events } = mk();
  c.start(); ws().open(); ws().recvJson(welcome);
  ws().recvJson({ t: 'pane_state', pane: 'p', alt_screen: true });
  ws().recvJson({ t: 'session_killed', reason: 'kill switch' });
  assert.equal(events.find((e) => e[0] === 'pane_state')[1].alt_screen, true);
  assert.equal(events.find((e) => e[0] === 'session_killed')[1].reason, 'kill switch');
});
