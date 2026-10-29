// Key encoding for the phone toolbar. No DOM dependencies.

const ESC = '\x1b';

const CURSOR = { up: 'A', down: 'B', right: 'C', left: 'D', home: 'H', end: 'F' };
const TILDE = { pgup: '5', pgdn: '6', del: '3', ins: '2' };

/** xterm modifier parameter: 1 + (shift 1, alt 2, ctrl 4). */
function modParam({ ctrl, alt }) {
  return 1 + (alt ? 2 : 0) + (ctrl ? 4 : 0);
}

/**
 * Named key -> string of bytes to send. Unknown names return ''.
 * appCursor mirrors term.modes.applicationCursorKeysMode (DECCKM).
 */
export function keySequence(name, { appCursor = false, ctrl = false, alt = false } = {}) {
  const mod = ctrl || alt;
  if (name in CURSOR) {
    const c = CURSOR[name];
    if (mod) return `${ESC}[1;${modParam({ ctrl, alt })}${c}`;
    return appCursor ? `${ESC}O${c}` : `${ESC}[${c}`;
  }
  if (name in TILDE) {
    return mod ? `${ESC}[${TILDE[name]};${modParam({ ctrl, alt })}~` : `${ESC}[${TILDE[name]}~`;
  }
  switch (name) {
    case 'esc':
      return ESC;
    case 'tab':
      return alt ? `${ESC}\t` : '\t';
    case 'enter':
      return '\r';
    case 'backspace':
      return '\x7f';
    case 'ctrl-c':
      return '\x03';
    default:
      return '';
  }
}

/** Ctrl-modified code for a single character, or null if there is no control code for it. */
export function ctrlChar(ch) {
  if (ch.length !== 1) return null;
  const c = ch.charCodeAt(0);
  if (c >= 0x61 && c <= 0x7a) return String.fromCharCode(c - 0x60); // a-z
  if (c >= 0x40 && c <= 0x5f) return String.fromCharCode(c - 0x40); // @ A-Z [ \ ] ^ _
  if (ch === ' ') return '\x00';
  if (ch === '?') return '\x7f';
  return null;
}

/**
 * Apply one-shot sticky Ctrl/Alt (toolbar toggles) to text coming from the keyboard.
 * Only plain text is modified: sequences starting with ESC (already-encoded keys) pass through.
 * Returns {data, used}; `used` says whether a modifier was applied (so the UI can clear the toggle).
 */
export function applyStickyModifiers(text, { ctrl = false, alt = false } = {}) {
  if (!text || (!ctrl && !alt) || text.charCodeAt(0) === 0x1b) return { data: text, used: false };
  // Take the first code point only; the rest (e.g. an IME burst) is sent unmodified.
  const first = String.fromCodePoint(text.codePointAt(0));
  const rest = text.slice(first.length);
  let out = first;
  if (ctrl) {
    const c = ctrlChar(first);
    if (c !== null) out = c;
  }
  if (alt) out = ESC + out;
  return { data: out + rest, used: true };
}

/** Wrap pasted text per bracketed-paste mode; also normalises newlines to CR like a terminal paste. */
export function formatPaste(text, bracketed) {
  const t = text.replace(/\r\n|\n/g, '\r');
  return bracketed ? `\x1b[200~${t}\x1b[201~` : t;
}

/** Toolbar layout (data only). `kind`: key (named sequence), text (literal), toggle (ctrl/alt). */
export const TOOLBAR_ROWS = [
  [
    { label: 'Esc', kind: 'key', key: 'esc' },
    { label: 'Ctrl', kind: 'toggle', mod: 'ctrl' },
    { label: 'Alt', kind: 'toggle', mod: 'alt' },
    { label: 'Tab', kind: 'key', key: 'tab' },
    { label: '↑', aria: 'Up', kind: 'key', key: 'up' },
    { label: '↓', aria: 'Down', kind: 'key', key: 'down' },
    { label: '←', aria: 'Left', kind: 'key', key: 'left' },
    { label: '→', aria: 'Right', kind: 'key', key: 'right' },
    { label: 'Home', kind: 'key', key: 'home' },
    { label: 'End', kind: 'key', key: 'end' },
    { label: 'PgUp', kind: 'key', key: 'pgup' },
    { label: 'PgDn', kind: 'key', key: 'pgdn' },
    { label: '^C', aria: 'Control C', kind: 'key', key: 'ctrl-c' },
  ],
  [
    ...['|', '~', '/', '\\', '-', '_', '`', '$', '&', '*', '<', '>', '"', "'"].map((s) => ({ label: s, kind: 'text', text: s })),
    { label: 'Paste', kind: 'action', action: 'paste' },
    { label: 'Copy', kind: 'action', action: 'copy' },
    { label: 'Kbd', aria: 'Show or hide keyboard', kind: 'action', action: 'keyboard' },
  ],
];
