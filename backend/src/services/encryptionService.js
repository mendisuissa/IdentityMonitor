'use strict';
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PREFIX    = 'enc:v1:';

// #105: scryptSync costs ~40 ms of CPU and a 16 MB off-heap buffer per call. It ran on every
// encrypt/decrypt, and a burst of settings reads (one per open alert in the automation sweep)
// turned it into multi-minute event-loop stalls. The key only changes with ENCRYPTION_KEY, so
// it is derived once per value.
let _keyCache = { raw: null, key: null };

function getKey() {
  const raw = process.env.ENCRYPTION_KEY || '';
  if (!raw) {
    throw new Error('ENCRYPTION_KEY environment variable is not set. Cannot encrypt/decrypt secrets.');
  }
  if (_keyCache.raw === raw) return _keyCache.key;
  const key = /^[0-9a-f]{64}$/i.test(raw)
    ? Buffer.from(raw, 'hex')
    : crypto.scryptSync(raw, 'identitymonitor-salt-v1', 32);
  _keyCache = { raw, key };
  return key;
}

function encrypt(plaintext) {
  if (!plaintext) return plaintext;
  if (String(plaintext).startsWith(PREFIX)) return plaintext; // already encrypted

  const key = getKey();
  const iv  = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return `${PREFIX}${iv.toString('hex')}:${tag.toString('hex')}:${encrypted.toString('hex')}`;
}

function decrypt(ciphertext) {
  if (!ciphertext) return ciphertext;
  const str = String(ciphertext);
  if (!str.startsWith(PREFIX)) return str; // plaintext (legacy) — return as-is

  const parts = str.slice(PREFIX.length).split(':');
  if (parts.length !== 3) throw new Error('Invalid encrypted value format.');

  const [ivHex, tagHex, dataHex] = parts;
  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  const decrypted = Buffer.concat([decipher.update(Buffer.from(dataHex, 'hex')), decipher.final()]);
  return decrypted.toString('utf8');
}

function isEncrypted(value) {
  return typeof value === 'string' && value.startsWith(PREFIX);
}

module.exports = { encrypt, decrypt, isEncrypted };
