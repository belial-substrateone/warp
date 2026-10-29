// Persistence helpers. localStorage can throw or be absent (private mode); every access is guarded.
// Documented weaker than native: the device token sits in localStorage (REMOTE_CONTROL.md section 6).

const KEY = 'anonwarp.pairing.v1';
const PREFS = 'anonwarp.prefs.v1';

function backend(storage) {
  if (storage) return storage;
  try {
    return globalThis.localStorage || null;
  } catch {
    return null;
  }
}

function readJson(storage, key) {
  try {
    const s = backend(storage);
    const raw = s && s.getItem(key);
    const v = raw ? JSON.parse(raw) : null;
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

function writeJson(storage, key, value) {
  try {
    const s = backend(storage);
    if (!s) return false;
    s.setItem(key, JSON.stringify(value));
    return true;
  } catch {
    return false;
  }
}

/** {token, deviceId, instance, pcName, hosts[], pairedAt} or null. */
export function loadPairing(storage) {
  const p = readJson(storage, KEY);
  return p && typeof p.token === 'string' && p.token ? p : null;
}

export function savePairing(p, storage) {
  return writeJson(storage, KEY, p);
}

export function clearPairing(storage) {
  try {
    const s = backend(storage);
    if (s) s.removeItem(KEY);
  } catch {
    /* ignore */
  }
}

export function loadPrefs(storage) {
  return readJson(storage, PREFS) || {};
}

export function savePrefs(patch, storage) {
  return writeJson(storage, PREFS, { ...loadPrefs(storage), ...patch });
}
