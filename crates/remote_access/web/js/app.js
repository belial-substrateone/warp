// AnonWarp remote web client UI. All remote-supplied strings are rendered with textContent only.
import {
  RemoteClient, pairDevice, revokeSelf, parsePairFragment, fingerprintToGroups, CLOSE,
} from './protocol.js';
import { keySequence, applyStickyModifiers, formatPaste, TOOLBAR_ROWS } from './keys.js';
import { loadPairing, savePairing, clearPairing, loadPrefs, savePrefs } from './store.js';

const $ = (id) => document.getElementById(id);
const IS_PAIR_ROUTE = location.pathname === '/pair' || location.pathname === '/pair/';

// ---------------------------------------------------------------- generic UI helpers

function el(tag, props = {}, text) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  if (text !== undefined) e.textContent = text;
  return e;
}

function show(screen) {
  $('screen-message').hidden = screen !== 'message';
  $('screen-main').hidden = screen !== 'main';
  if (screen !== 'main') closeSheet();
}

/** tone: '' | 'bad' | 'warn' | 'ok' */
function showMessage({ title, text, tone = '', actions = [], fingerprint = '', spinner = false }) {
  $('msg-title').textContent = title;
  $('msg-text').textContent = text || '';
  $('msg-title').parentElement.className = `card ${tone}`;
  $('msg-fp').hidden = !fingerprint;
  $('msg-fp-value').textContent = fingerprint;
  $('msg-spinner').hidden = !spinner;
  const box = $('msg-actions');
  box.replaceChildren(...actions.map((a) => el('button', { type: 'button', class: a.primary ? 'primary' : (a.danger ? 'danger' : ''), onclick: a.onClick }, a.label)));
  show('message');
}

function deviceName() {
  const ua = navigator.userAgent || '';
  const os = /Android/.test(ua) ? 'Android' : /iPhone|iPad|iPod/.test(ua) ? 'iOS' : /Mac OS X/.test(ua) ? 'macOS' : /Windows/.test(ua) ? 'Windows' : /Linux/.test(ua) ? 'Linux' : 'Unknown OS';
  const br = /Firefox\//.test(ua) ? 'Firefox' : /Edg\//.test(ua) ? 'Edge' : /Chrome\//.test(ua) ? 'Chrome' : /Safari\//.test(ua) ? 'Safari' : 'Browser';
  return `Web (${br} on ${os})`;
}

const origin = location.origin;
const wsUrl = () => `${location.protocol === 'https:' ? 'wss:' : 'ws:'}//${location.host}/v1/ws`;
const boundFetch = (...a) => fetch(...a);

// ---------------------------------------------------------------- pairing route

let pairAbort = null;

async function runPairing() {
  const parsed = parsePairFragment(location.hash);
  // Strip the secret from the URL/history immediately, before any network activity.
  try { history.replaceState(null, '', location.pathname); } catch { /* ignore */ }

  if (!parsed.ok) {
    const why = {
      missing: 'This page needs the pairing link from the QR code. Open AnonWarp on your PC, enable remote access and scan the QR code again.',
      missing_secret: 'The QR code is missing its pairing secret.',
      bad_secret: 'The pairing secret in the QR code is malformed.',
      bad_version: 'This QR code was made by a different, incompatible version of AnonWarp.',
      malformed: 'The pairing link could not be read.',
    }[parsed.reason] || 'The pairing link is not valid.';
    showMessage({ title: 'Invalid QR code', text: why, tone: 'bad', actions: [{ label: 'Back', onClick: () => location.replace('/') }] });
    return;
  }

  const fingerprint = fingerprintToGroups(parsed.fp);
  const pcName = parsed.name || 'your PC';
  const finish = (opts) => showMessage({ fingerprint, ...opts });
  const retry = { label: 'Scan a new QR code', onClick: () => location.replace('/') };

  pairAbort = new AbortController();
  const cancel = { label: 'Cancel', onClick: () => { pairAbort.abort(); location.replace('/'); } };
  finish({
    title: 'Pairing', spinner: true,
    text: `Contacting ${pcName}...${parsed.expiredHint ? ' (This QR code may have expired; if pairing fails, show a new one.)' : ''}`,
    actions: [cancel],
  });

  const res = await pairDevice({
    fetch: boundFetch, base: '', secret: parsed.secret, deviceName: deviceName(), platform: 'web', signal: pairAbort.signal,
    onState: (s) => {
      if (s === 'pending') {
        finish({ title: 'Waiting for approval', spinner: true, text: `Approve "${deviceName()}" on ${pcName}. Check that the fingerprint matches before approving.`, actions: [cancel] });
      }
    },
  });

  switch (res.status) {
    case 'approved': {
      savePairing({
        token: res.token, deviceId: res.deviceId, instance: parsed.id, pcName: parsed.name,
        hosts: parsed.hosts, origin, pairedAt: Date.now(),
      });
      try { history.replaceState(null, '', '/'); } catch { /* ignore */ }
      startSession();
      return;
    }
    case 'denied':
      finish({ title: 'Pairing denied', text: `${pcName} denied this device.`, tone: 'bad', actions: [retry] });
      return;
    case 'expired':
      finish({ title: 'Pairing expired', text: 'The approval request timed out. Show a new QR code on your PC and scan it again.', tone: 'warn', actions: [retry] });
      return;
    case 'invalid':
      finish({ title: 'QR code rejected', text: 'The pairing secret is wrong, already used, or expired. Show a new QR code on your PC and scan it.', tone: 'bad', actions: [retry] });
      return;
    case 'locked': {
      let left = res.retryAfter;
      const tick = () => {
        finish({
          title: 'Too many attempts', tone: 'warn',
          text: left > 0 ? `Pairing is temporarily locked. Try again in ${left} s with a new QR code.` : 'You can try again now with a new QR code.',
          actions: [retry],
        });
        if (left-- > 0) setTimeout(tick, 1000);
      };
      tick();
      return;
    }
    case 'cancelled':
      return;
    default:
      finish({ title: 'Could not pair', text: `Network error: ${res.message || 'unknown'}. Make sure your phone is on the same network (or Tailscale) as your PC.`, tone: 'bad', actions: [retry] });
  }
}

// ---------------------------------------------------------------- main session

let client = null;
let term = null;
let fit = null;
let tree = { windows: [] };
let currentPane = null; // pane id string
let welcomeInfo = {};
let ctrlOn = false;
let altOn = false;
let prefs = loadPrefs();
let fontSize = Math.min(32, Math.max(6, Number(prefs.fontSize) || 14));
let paneMeta = { cols: 80, rows: 24, alt: false };
let sessionStarted = false;

function setStatus(state, text) {
  $('statusbar').dataset.state = state;
  $('conn-text').textContent = text;
  if (state !== 'ready') $('conn-latency').textContent = '';
}

function ensureTerminal() {
  if (term) return;
  term = new window.Terminal({
    fontSize, cols: 80, rows: 24, scrollback: 5000, cursorBlink: true,
    fontFamily: 'ui-monospace, Menlo, Consolas, "DejaVu Sans Mono", monospace',
    allowProposedApi: false, macOptionIsMeta: true,
    theme: { background: '#000000', foreground: '#e6edf3' },
  });
  fit = new window.FitAddon.FitAddon();
  term.loadAddon(fit);
  try { term.loadAddon(new window.WebLinksAddon.WebLinksAddon()); } catch { /* optional */ }
  term.open($('term'));
  const ta = term.textarea;
  if (ta) {
    ta.setAttribute('inputmode', 'text');
    ta.setAttribute('autocapitalize', 'off');
    ta.setAttribute('autocorrect', 'off');
    ta.setAttribute('autocomplete', 'off');
    ta.setAttribute('spellcheck', 'false');
  }
  term.onData((d) => sendKeyboardText(d));
  term.onBinary((s) => client && client.sendInput(Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff)));
}

function sendKeyboardText(text) {
  if (!client) return;
  const r = applyStickyModifiers(text, { ctrl: ctrlOn, alt: altOn });
  if (r.used) { setToggle('ctrl', false); setToggle('alt', false); }
  client.sendInput(r.data);
}

function sendNamedKey(name) {
  if (!client) return;
  const appCursor = !!(term && term.modes && term.modes.applicationCursorKeysMode);
  const seq = keySequence(name, { appCursor, ctrl: ctrlOn, alt: altOn });
  if (!seq) return;
  if (ctrlOn || altOn) { setToggle('ctrl', false); setToggle('alt', false); }
  client.sendInput(seq);
}

function setToggle(mod, on) {
  if (mod === 'ctrl') ctrlOn = on; else altOn = on;
  const b = document.querySelector(`#toolbar button[data-mod="${mod}"]`);
  if (b) b.setAttribute('aria-pressed', String(on));
}

function buildToolbar() {
  const bar = $('toolbar');
  bar.replaceChildren();
  for (const row of TOOLBAR_ROWS) {
    const r = el('div', { class: 'tb-row' });
    for (const k of row) {
      const b = el('button', { type: 'button' }, k.label);
      if (k.aria) b.setAttribute('aria-label', k.aria);
      if (k.kind === 'toggle') { b.dataset.mod = k.mod; b.setAttribute('aria-pressed', 'false'); }
      // Keep focus (and the on-screen keyboard) in the terminal textarea.
      b.addEventListener('pointerdown', (e) => e.preventDefault());
      b.addEventListener('mousedown', (e) => e.preventDefault());
      b.addEventListener('click', () => {
        if (k.kind === 'key') sendNamedKey(k.key);
        else if (k.kind === 'text') sendKeyboardText(k.text);
        else if (k.kind === 'toggle') setToggle(k.mod, !(k.mod === 'ctrl' ? ctrlOn : altOn));
        else if (k.action === 'paste') doPaste();
        else if (k.action === 'copy') doCopy();
        else if (k.action === 'keyboard') toggleKeyboard();
      });
      r.append(b);
    }
    bar.append(r);
  }
}

async function doPaste() {
  let text = '';
  try { text = await navigator.clipboard.readText(); } catch { text = window.prompt('Paste text to send:') || ''; }
  if (text && client) client.sendInput(formatPaste(text, !!(term && term.modes.bracketedPasteMode)));
}

async function doCopy() {
  const sel = term ? term.getSelection() : '';
  if (!sel) { flashStatus('Nothing selected'); return; }
  try { await navigator.clipboard.writeText(sel); flashStatus('Copied'); } catch { window.prompt('Copy this text:', sel); }
}

let flashTimer = null;
function flashStatus(msg) {
  const prev = $('conn-text').textContent;
  $('conn-text').textContent = msg;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { if ($('conn-text').textContent === msg) $('conn-text').textContent = prev; }, 1200);
}

function toggleKeyboard() {
  const ta = term && term.textarea;
  if (!ta) return;
  if (document.activeElement === ta) ta.blur(); else term.focus();
}

// ---- tree / tabs / panes

function flatTabs() {
  const out = [];
  const multi = tree.windows.length > 1;
  tree.windows.forEach((w, wi) => {
    for (const t of w.tabs || []) out.push({ win: wi, label: (multi ? `W${wi + 1}: ` : '') + (t.title || 'Tab'), tab: t });
  });
  return out;
}

function findPane(id) {
  for (const w of tree.windows) for (const t of w.tabs || []) for (const p of t.panes || []) if (p.id === id) return { tab: t, pane: p, win: w };
  return null;
}

function pickDefaultPane() {
  if (currentPane && findPane(currentPane)) return currentPane;
  const stored = prefs.lastPane;
  if (stored && findPane(stored)) return stored;
  for (const w of tree.windows) for (const t of w.tabs || []) if (t.active) { const p = (t.panes || []).find((x) => x.focused) || (t.panes || [])[0]; if (p) return p.id; }
  const first = flatTabs()[0];
  return first && first.tab.panes && first.tab.panes[0] ? first.tab.panes[0].id : null;
}

function renderTabs() {
  const bar = $('tabbar');
  const cur = currentPane ? findPane(currentPane) : null;
  bar.setAttribute('role', 'tablist');
  bar.replaceChildren(...flatTabs().map(({ label, tab }) => {
    const b = el('button', { type: 'button', role: 'tab', 'aria-selected': String(!!cur && cur.tab.id === tab.id) }, label);
    b.addEventListener('click', () => {
      const p = (tab.panes || []).find((x) => x.focused) || (tab.panes || [])[0];
      if (p) switchPane(p.id);
    });
    return b;
  }));
  const pb = $('panebar');
  const panes = cur ? cur.tab.panes || [] : [];
  pb.hidden = panes.length < 2;
  pb.replaceChildren(...panes.map((p, i) => {
    const b = el('button', { type: 'button', 'aria-selected': String(p.id === currentPane) }, `${i + 1}: ${p.title || p.cwd || 'pane'}`);
    b.addEventListener('click', () => switchPane(p.id));
    return b;
  }));
}

function switchPane(id) {
  if (!id) return;
  currentPane = id;
  savePrefs({ lastPane: id });
  prefs = loadPrefs();
  client.attach(id);
  renderTabs();
  updateInfo();
}

function updateInfo() {
  const cur = currentPane ? findPane(currentPane) : null;
  const dev = welcomeInfo.device ? `Device: ${welcomeInfo.device}. ` : '';
  const pane = cur ? `Pane ${paneMeta.cols}x${paneMeta.rows}${paneMeta.alt ? ' (alt screen)' : ''}${cur.pane.cwd ? ` in ${cur.pane.cwd}` : ''}. ` : '';
  const stored = loadPairing();
  $('sheet-info').textContent = `${stored && stored.pcName ? `PC: ${stored.pcName}. ` : ''}${dev}${pane}${welcomeInfo.server || ''}`;
}

// ---- menu sheet

function openSheet() { $('sheet').hidden = false; $('sheet-backdrop').hidden = false; updateInfo(); $('sheet-close').focus(); }
function closeSheet() { $('sheet').hidden = true; $('sheet-backdrop').hidden = true; }

function applyFont(n) {
  fontSize = Math.min(32, Math.max(6, Math.round(n)));
  $('font-val').textContent = String(fontSize);
  if (term) term.options.fontSize = fontSize;
  savePrefs({ fontSize });
}

function fitWidth() {
  if (!term) return;
  const screen = term.element && term.element.querySelector('.xterm-screen');
  const wrap = $('term-wrap');
  if (!screen || !screen.offsetWidth) return;
  applyFont(fontSize * (wrap.clientWidth - 6) / screen.offsetWidth);
}

async function doAction(name, target, params, confirmText) {
  if (confirmText && !window.confirm(confirmText)) return;
  closeSheet();
  const cur = currentPane ? findPane(currentPane) : null;
  const t = target === 'tab' ? { tab: cur && cur.tab.id } : target === 'pane' ? { pane: currentPane } : {};
  const res = await client.action(name, t, params || {});
  if (!res.ok) flashStatus(`Failed: ${(res.error && res.error.message) || 'error'}`);
}

function wireMenu() {
  $('btn-menu').addEventListener('click', openSheet);
  $('sheet-close').addEventListener('click', closeSheet);
  $('sheet-backdrop').addEventListener('click', closeSheet);
  $('font-dec').addEventListener('click', () => applyFont(fontSize - 1));
  $('font-inc').addEventListener('click', () => applyFont(fontSize + 1));
  $('font-fit').addEventListener('click', fitWidth);
  $('act-newtab').addEventListener('click', () => doAction('tab.create', 'none', {}));
  $('act-split-right').addEventListener('click', () => doAction('pane.split', 'pane', { direction: 'right' }));
  $('act-split-down').addEventListener('click', () => doAction('pane.split', 'pane', { direction: 'down' }));
  $('act-close-pane').addEventListener('click', () => doAction('pane.close', 'pane', {}, 'Close this pane on your PC?'));
  $('act-close-tab').addEventListener('click', () => doAction('tab.close', 'tab', {}, 'Close this tab on your PC?'));
  $('act-reconnect').addEventListener('click', () => { closeSheet(); client.reconnectNow(); });
  $('act-disconnect').addEventListener('click', () => {
    closeSheet();
    client.stop();
    showMessage({ title: 'Disconnected', text: 'You disconnected from your PC.', actions: [{ label: 'Reconnect', primary: true, onClick: () => startSession() }, { label: 'Forget this PC', danger: true, onClick: () => unpair() }] });
  });
  $('act-unpair').addEventListener('click', unpair);
  $('btn-phone-resize').addEventListener('click', () => {
    const d = fit && fit.proposeDimensions();
    if (d && Number.isFinite(d.cols) && Number.isFinite(d.rows)) { client.sendResize(d.cols, d.rows); closeSheet(); }
  });
  $('font-val').textContent = String(fontSize);
}

async function unpair() {
  if (!window.confirm('Forget this PC? This phone will be unpaired and must scan a new QR code to connect again.')) return;
  const p = loadPairing();
  if (client) client.stop();
  let remote = false;
  if (p) remote = await revokeSelf({ fetch: boundFetch, base: '', token: p.token });
  clearPairing();
  showMessage({
    title: 'Unpaired', tone: 'ok',
    text: remote ? 'This phone was removed from your PC.' : 'Pairing data was removed from this phone. The PC could not be reached, so also remove this device in AnonWarp settings on your PC.',
    actions: [{ label: 'Done', primary: true, onClick: () => location.replace('/') }],
  });
}

// ---- session lifecycle

function startSession() {
  const pairing = loadPairing();
  if (!pairing) {
    showMessage({
      title: 'Not paired', text: 'Open AnonWarp on your PC, enable remote access and scan the QR code with this phone\'s camera.',
      actions: [{ label: 'Retry', onClick: () => location.reload() }],
    });
    return;
  }
  show('main');
  ensureTerminal();
  if (!sessionStarted) { buildToolbar(); wireMenu(); wireViewport(); sessionStarted = true; }
  if (client) client.stop();
  tree = { windows: [] };
  client = new RemoteClient({ url: wsUrl(), token: pairing.token, clientName: 'web' });

  client.on('state', (s) => {
    switch (s.state) {
      case 'connecting': setStatus('connecting', 'Connecting...'); break;
      case 'authenticating': setStatus('connecting', 'Authenticating...'); break;
      case 'ready': setStatus('ready', 'Connected'); break;
      case 'reconnecting': {
        const secs = Math.ceil((s.delay || 0) / 1000);
        setStatus('reconnecting', s.delay === undefined ? 'Reconnecting...' : `Disconnected, retry ${s.attempt} in ${secs}s${s.code === CLOSE.RATE_LIMITED ? ' (rate limited)' : ''}`);
        break;
      }
      case 'stopped': setStatus('stopped', 'Disconnected'); break;
      case 'fatal': setStatus('fatal', 'Connection closed'); break;
      default: break;
    }
  });
  client.on('welcome', (w) => {
    welcomeInfo = w || {};
    $('row-phone-resize').hidden = !welcomeInfo.phone_resize;
    updateInfo();
  });
  client.on('latency', ({ ms }) => { $('conn-latency').textContent = `${ms} ms`; });
  client.on('tree', (m) => {
    tree = { windows: Array.isArray(m.windows) ? m.windows : [] };
    const want = pickDefaultPane();
    if (want && want !== client.paneId) switchPane(want);
    else { currentPane = want; renderTabs(); }
  });
  client.on('snapshot', (s) => {
    term.reset();
    const cols = Math.max(1, Math.min(500, Number(s.cols) || 80));
    const rows = Math.max(1, Math.min(300, Number(s.rows) || 24));
    paneMeta = { cols, rows, alt: !!s.alt_screen };
    term.resize(cols, rows);
    updateInfo();
  });
  client.on('output', ({ bytes }) => term.write(bytes));
  client.on('pane_state', (m) => {
    if (m.pane === currentPane) { paneMeta.alt = !!m.alt_screen; updateInfo(); }
  });
  client.on('pane_closed', (m) => {
    if (m.pane === currentPane) { currentPane = null; client.list(); }
  });
  client.on('session_killed', (m) => {
    killReason = (m && typeof m.reason === 'string') ? m.reason : '';
  });
  client.on('error', (m) => {
    if (m && m.code === 'resize_denied') flashStatus('PC does not allow resizing');
    else flashStatus(`Error: ${m && m.code ? m.code : 'unknown'}`);
  });
  client.on('fatal', onFatal);
  client.start();
}

let killReason = '';

function onFatal({ code, reason }) {
  const again = { label: 'Reconnect', primary: true, onClick: () => { killReason = ''; startSession(); } };
  const forget = { label: 'Forget this PC', danger: true, onClick: () => { clearPairing(); location.replace('/'); } };
  if (code === CLOSE.KILLED) {
    showMessage({
      title: 'Session ended by your PC', tone: 'bad',
      text: `${killReason || reason || 'Remote access was stopped or this device was revoked on your PC.'} If this device was revoked you need to pair again.`,
      actions: [again, forget],
    });
  } else if (code === CLOSE.AUTH) {
    showMessage({
      title: 'Not authorized', tone: 'bad',
      text: 'The PC did not accept this device (authentication failed or timed out). If it was removed on the PC, forget it here and pair again.',
      actions: [again, forget],
    });
  } else {
    showMessage({
      title: 'Connection refused', tone: 'bad',
      text: `The PC closed the connection (code ${code}${reason ? `: ${reason}` : ''}). This web client may be incompatible with your AnonWarp version.`,
      actions: [again, forget],
    });
  }
}

function wireViewport() {
  // Track the visual viewport so the toolbar stays above the on-screen keyboard.
  const vv = window.visualViewport;
  const apply = () => document.documentElement.style.setProperty('--vh', `${Math.round(vv ? vv.height : window.innerHeight)}px`);
  if (vv) { vv.addEventListener('resize', apply); vv.addEventListener('scroll', () => window.scrollTo(0, 0)); }
  window.addEventListener('resize', apply);
  apply();
  document.addEventListener('visibilitychange', () => { if (!document.hidden && client) client.reconnectNow(); });
  window.addEventListener('online', () => { if (client) client.reconnectNow(); });
  // Tapping the terminal focuses it (opens the keyboard).
  $('term-wrap').addEventListener('click', (e) => { if (e.target === $('term-wrap') && term) term.focus(); });
}

// ---------------------------------------------------------------- boot

if (IS_PAIR_ROUTE) runPairing();
else if (loadPairing()) startSession();
else {
  showMessage({
    title: 'Not paired',
    text: 'Open AnonWarp on your PC, enable remote access, and scan the QR code shown there with this phone\'s camera.',
  });
}
