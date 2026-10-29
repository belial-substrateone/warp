import test from 'node:test';
import assert from 'node:assert/strict';
import { keySequence, ctrlChar, applyStickyModifiers, formatPaste, TOOLBAR_ROWS } from '../js/keys.js';
import { loadPairing, savePairing, clearPairing, loadPrefs, savePrefs } from '../js/store.js';

test('named keys, DECCKM-dependent arrows', () => {
  assert.equal(keySequence('esc'), '\x1b');
  assert.equal(keySequence('tab'), '\t');
  assert.equal(keySequence('up'), '\x1b[A');
  assert.equal(keySequence('up', { appCursor: true }), '\x1bOA');
  assert.equal(keySequence('left', { appCursor: true }), '\x1bOD');
  assert.equal(keySequence('home'), '\x1b[H');
  assert.equal(keySequence('end', { appCursor: true }), '\x1bOF');
  assert.equal(keySequence('pgup'), '\x1b[5~');
  assert.equal(keySequence('pgdn'), '\x1b[6~');
  assert.equal(keySequence('ctrl-c'), '\x03');
  assert.equal(keySequence('nope'), '');
});

test('modifier-carrying keys use CSI 1;m form regardless of DECCKM', () => {
  assert.equal(keySequence('right', { ctrl: true }), '\x1b[1;5C');
  assert.equal(keySequence('right', { alt: true, appCursor: true }), '\x1b[1;3C');
  assert.equal(keySequence('left', { ctrl: true, alt: true }), '\x1b[1;7D');
  assert.equal(keySequence('pgup', { ctrl: true }), '\x1b[5;5~');
  assert.equal(keySequence('tab', { alt: true }), '\x1b\t');
});

test('ctrlChar', () => {
  assert.equal(ctrlChar('c'), '\x03'); assert.equal(ctrlChar('C'), '\x03');
  assert.equal(ctrlChar('['), '\x1b'); assert.equal(ctrlChar('\\'), '\x1c');
  assert.equal(ctrlChar(' '), '\x00'); assert.equal(ctrlChar('?'), '\x7f');
  assert.equal(ctrlChar('1'), null); assert.equal(ctrlChar('ab'), null);
});

test('sticky modifiers', () => {
  assert.deepEqual(applyStickyModifiers('c', { ctrl: true }), { data: '\x03', used: true });
  assert.deepEqual(applyStickyModifiers('x', { alt: true }), { data: '\x1bx', used: true });
  assert.deepEqual(applyStickyModifiers('d', { ctrl: true, alt: true }), { data: '\x1b\x04', used: true });
  assert.deepEqual(applyStickyModifiers('c', {}), { data: 'c', used: false });
  assert.deepEqual(applyStickyModifiers('\x1b[A', { ctrl: true }), { data: '\x1b[A', used: false });
  assert.deepEqual(applyStickyModifiers('1', { ctrl: true }), { data: '1', used: true }); // no ctrl code: unchanged, toggle consumed
  assert.deepEqual(applyStickyModifiers('cd', { ctrl: true }), { data: '\x03d', used: true });
  assert.deepEqual(applyStickyModifiers('', { ctrl: true }), { data: '', used: false });
});

test('paste formatting', () => {
  assert.equal(formatPaste('a\nb\r\nc', false), 'a\rb\rc');
  assert.equal(formatPaste('ls', true), '\x1b[200~ls\x1b[201~');
});

test('toolbar has the required keys', () => {
  const labels = TOOLBAR_ROWS.flat().map((k) => k.label);
  for (const l of ['Esc', 'Ctrl', 'Alt', 'Tab', 'Home', 'End', 'PgUp', 'PgDn', '|', '~', '/', '\\', '-', '_', 'Paste', 'Copy']) assert.ok(labels.includes(l), l);
});

test('store: round trip, bad json, throwing storage', () => {
  const mem = new Map();
  const st = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, v), removeItem: (k) => mem.delete(k) };
  assert.equal(loadPairing(st), null);
  assert.equal(savePairing({ token: 'T', pcName: 'x' }, st), true);
  assert.equal(loadPairing(st).token, 'T');
  clearPairing(st);
  assert.equal(loadPairing(st), null);
  mem.set('anonwarp.pairing.v1', '{bad');
  assert.equal(loadPairing(st), null);
  mem.set('anonwarp.pairing.v1', JSON.stringify({ nottoken: 1 }));
  assert.equal(loadPairing(st), null);
  savePrefs({ fontSize: 16 }, st); savePrefs({ lastPane: 'p' }, st);
  assert.deepEqual(loadPrefs(st), { fontSize: 16, lastPane: 'p' });
  const bad = { getItem() { throw new Error('x'); }, setItem() { throw new Error('x'); }, removeItem() { throw new Error('x'); } };
  assert.equal(loadPairing(bad), null); assert.equal(savePairing({ token: 't' }, bad), false); clearPairing(bad);
});
