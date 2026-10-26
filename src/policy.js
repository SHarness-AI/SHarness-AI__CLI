// Process Behaviour Policy, version 0, in JavaScript: parse, check the shape, canonicalise, hash.
//
// The standard is https://sharness.ai/code/standards/policy-v0/ and its test vectors are what this
// file is tested against. The hash is SHA-256 over canonical JSON: keys sorted, no whitespace,
// UTF-8, integers only. Where JavaScript and the reference implementation (Python) would differ,
// the policy is refused rather than hashed differently: floats (including 64.0 and 1e2, which
// JSON.parse would silently read as integers, so the text is scanned before it is parsed),
// integers beyond Number.MAX_SAFE_INTEGER, strings with lone surrogates, duplicate keys.
// Works in Node 20+ and in a browser: no dependencies, WebCrypto for the hash.

export const PBP_VERSION = 1;
export const MAX_FILE_SIZE = 1 << 20;
export const MAX_ID_LENGTH = 200;
const CONTROL = /[\x00-\x1f\x7f]/;
const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

export class PolicyError extends Error {}

// --- the text, before JSON.parse: duplicate keys and non-integer numbers are invisible after it
export function scan(text) {
  const stack = [];            // one Set of keys per open object, null per open array
  let i = 0, expectKey = false;
  const err = (m) => { throw new PolicyError(m); };
  const readString = () => {
    let s = '';
    for (i++; i < text.length; i++) {
      const c = text[i];
      if (c === '"') { i++; return s; }
      if (c === '\\') { s += c + text[i + 1]; i++; continue; }
      s += c;
    }
    err('unterminated string');
  };
  while (i < text.length) {
    const c = text[i];
    if (c === ' ' || c === '\n' || c === '\r' || c === '\t') { i++; continue; }
    if (c === '{') { stack.push(new Set()); expectKey = true; i++; continue; }
    if (c === '[') { stack.push(null); expectKey = false; i++; continue; }
    if (c === '}' || c === ']') { stack.pop(); expectKey = false; i++; continue; }
    if (c === ',') { expectKey = stack.length > 0 && stack[stack.length - 1] !== null; i++; continue; }
    if (c === ':') { expectKey = false; i++; continue; }
    if (c === '"') {
      const s = readString();
      if (expectKey) {
        const keys = stack[stack.length - 1];
        if (keys.has(s)) err(`duplicate key '${s}': a policy must say each thing once`);
        keys.add(s);
      }
      continue;
    }
    if (c === '-' || (c >= '0' && c <= '9')) {
      let j = i;
      while (j < text.length && /[-+0-9.eE]/.test(text[j])) j++;
      const tok = text.slice(i, j);
      if (/[.eE]/.test(tok)) err(`${tok}: floats are not allowed in a policy (integers only), so the hash is the same in every language`);
      i = j; continue;
    }
    i++;                       // true, false, null and anything else: JSON.parse judges it
  }
}

// --- the values: what canonical JSON refuses
function checkTypes(v, path) {
  if (v === null || typeof v === 'boolean') return;
  if (typeof v === 'number') {
    if (!Number.isInteger(v)) throw new PolicyError(`${path}: floats are not allowed in a policy (integers only)`);
    if (!Number.isSafeInteger(v)) throw new PolicyError(`${path}: integers must stay within ±${Number.MAX_SAFE_INTEGER}`);
    return;
  }
  if (typeof v === 'string') {
    if (LONE_SURROGATE.test(v)) throw new PolicyError(`${path}: string contains a lone surrogate, which has no UTF-8 form`);
    return;
  }
  if (Array.isArray(v)) { v.forEach((x, k) => checkTypes(x, `${path}[${k}]`)); return; }
  if (typeof v === 'object') { for (const k of Object.keys(v)) checkTypes(v[k], `${path}.${k}`); return; }
  throw new PolicyError(`${path}: unsupported type ${typeof v}`);
}

// Canonical JSON as a string: sorted keys, no whitespace, non-ASCII kept as is (JSON.stringify
// escapes only ", \ and the controls below 0x20, the same as Python's ensure_ascii=False).
export function canonical(v, path = '$') {
  checkTypes(v, path);
  const enc = (x) => {
    if (x === null || typeof x !== 'object') return JSON.stringify(x);
    if (Array.isArray(x)) return '[' + x.map(enc).join(',') + ']';
    return '{' + Object.keys(x).sort().map((k) => JSON.stringify(k) + ':' + enc(x[k])).join(',') + '}';
  };
  return enc(v);
}

export async function policyHash(v) {
  const bytes = new TextEncoder().encode(canonical(v));
  const digest = await globalThis.crypto.subtle.digest('SHA-256', bytes);
  return 'sha256:' + Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, '0')).join('');
}

// --- a policy file's text: refuses a duplicate key, a float, a non-object, more than a megabyte
export function parse(text, name = 'policy') {
  if (text.length > MAX_FILE_SIZE) throw new PolicyError(`${name}: larger than ${MAX_FILE_SIZE} bytes; a policy is a small file`);
  scan(text);
  let obj;
  try { obj = JSON.parse(text); } catch (e) { throw new PolicyError(`${name}: not JSON (${e.message})`); }
  if (obj === null || typeof obj !== 'object' || Array.isArray(obj)) throw new PolicyError(`${name}: a policy is a JSON object`);
  return obj;
}

// --- the shape of v0
function normpath(p) {
  const out = [];
  for (const s of p.split('/')) {
    if (s === '' || s === '.') continue;
    if (s === '..') { if (out.length) out.pop(); continue; }
    out.push(s);
  }
  return '/' + out.join('/');
}

export function pathProblem(p) {
  if (typeof p !== 'string' || !p.startsWith('/')) return 'must be an absolute path';
  if (CONTROL.test(p)) return 'contains a control character';
  if (p !== '/' && (normpath(p) !== p || p.endsWith('/') || p.startsWith('//'))) return `is not normalised (write it as '${normpath(p)}')`;
  return '';
}

const isInt = (x) => typeof x === 'number' && Number.isInteger(x);

export function check(policy) {
  const p = [];
  if (policy.pbp !== PBP_VERSION) p.push(`pbp must be ${PBP_VERSION}`);
  const id = policy.id;
  if (typeof id !== 'string' || !id) p.push('id must be a non-empty string');
  else if (id.length > MAX_ID_LENGTH || CONTROL.test(id)) p.push(`id must be at most ${MAX_ID_LENGTH} printable characters`);
  const files = policy.files;
  if (files === null || typeof files !== 'object' || Array.isArray(files)) p.push('files must be an object with read, write and exec lists');
  else {
    for (const k of ['read', 'write', 'exec']) {
      const v = files[k] ?? [];
      if (!Array.isArray(v)) { p.push(`files.${k} must be a list of absolute paths`); continue; }
      for (const x of v) { const why = pathProblem(x); if (why) p.push(`files.${k}: '${x}' ${why}`); }
    }
    for (const k of Object.keys(files)) if (!['read', 'write', 'exec'].includes(k)) p.push(`files.${k}: unknown key`);
  }
  const net = policy.network;
  if (net !== 'none') {
    if (net === null || typeof net !== 'object' || Array.isArray(net)) p.push('network must be "none" or {"connect_tcp_ports": [...]}');
    else {
      const ports = net.connect_tcp_ports;
      if (!Array.isArray(ports) || !ports.every((x) => isInt(x) && x > 0 && x < 65536)) p.push('network.connect_tcp_ports must be a list of ports (1-65535)');
      for (const k of Object.keys(net)) if (k !== 'connect_tcp_ports') p.push(`network.${k}: unknown key`);
    }
  }
  const proc = policy.process ?? {};
  if (proc === null || typeof proc !== 'object' || Array.isArray(proc) || (proc.no_new_privs ?? true) !== true) p.push('process.no_new_privs must be true (v0 always sets it)');
  else {
    for (const k of ['max_memory_mb', 'max_pids']) {
      const v = proc[k];
      if (v !== undefined && v !== null && (!isInt(v) || v < 0)) p.push(`process.${k} must be a non-negative integer`);
    }
    for (const k of Object.keys(proc)) if (!['no_new_privs', 'max_memory_mb', 'max_pids'].includes(k)) p.push(`process.${k}: unknown key`);
  }
  for (const k of Object.keys(policy)) if (!['pbp', 'id', 'layer', 'files', 'network', 'process', 'notes'].includes(k)) p.push(`${k}: unknown key`);
  try { canonical(policy); } catch (e) { if (e instanceof PolicyError) p.push(e.message); else throw e; }
  return p;
}

export function summary(policy) {
  const f = policy.files ?? {};
  const net = policy.network;
  const netS = net === 'none' ? 'none' : `tcp connect to ports ${JSON.stringify(net?.connect_tcp_ports)}`;
  const proc = policy.process ?? {};
  const caps = ['max_memory_mb', 'max_pids'].filter((k) => proc[k] != null).map((k) => `; ${k.replace('max_', 'max ')} ${proc[k]}`).join('');
  return `read ${(f.read ?? []).length} path(s), write ${(f.write ?? []).length}, exec ${(f.exec ?? []).length}; network ${netS}${caps}`;
}
