// Shared fakes for the node tests: deterministic clock + WebSocket.
export class FakeClock {
  constructor() { this.t = 0; this.next = 1; this.q = new Map(); }
  setTimeout(fn, ms) { const id = this.next++; this.q.set(id, { at: this.t + ms, fn }); return id; }
  clearTimeout(id) { this.q.delete(id); }
  now() { return this.t; }
  advance(ms) {
    const end = this.t + ms;
    for (;;) {
      let best = null;
      for (const [id, e] of this.q) if (e.at <= end && (!best || e.at < best[1].at)) best = [id, e];
      if (!best) break;
      this.q.delete(best[0]);
      this.t = Math.max(this.t, best[1].at);
      best[1].fn();
    }
    this.t = end;
  }
  get pending() { return this.q.size; }
  api() { return { setTimeout: (f, m) => this.setTimeout(f, m), clearTimeout: (i) => this.clearTimeout(i), now: () => this.now() }; }
}

export class FakeWS {
  static instances = [];
  static reset() { FakeWS.instances = []; }
  constructor(url, proto) {
    this.url = url; this.protocol = proto; this.readyState = 0; this.sent = []; this.closed = null;
    FakeWS.instances.push(this);
  }
  send(d) { this.sent.push(d); }
  close(code, reason) { this.closed = { code, reason }; this.readyState = 3; }
  // test drivers
  open() { this.readyState = 1; this.onopen && this.onopen({}); }
  recv(data) { this.onmessage && this.onmessage({ data }); }
  recvJson(o) { this.recv(JSON.stringify(o)); }
  serverClose(code, reason = '') { this.readyState = 3; this.onclose && this.onclose({ code, reason }); }
  sentJson() { return this.sent.filter((s) => typeof s === 'string').map((s) => JSON.parse(s)); }
  sentBinary() { return this.sent.filter((s) => typeof s !== 'string'); }
}

export function jsonResponse(status, body) {
  return { status, ok: status >= 200 && status < 300, json: async () => body };
}
