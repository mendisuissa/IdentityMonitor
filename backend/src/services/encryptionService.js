'use strict';
const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const PREFIX    = 'enc:v1:';

function getKey() {
  const raw = process.env.ENCRYPTION_KEY || '';
  if (!raw) {
    throw new Error('ENCRYPTION_KEY environment variable is not set. Cannot encrypt/decrypt secrets.');
  }
  if (/^[0-9a-f]{64}$/i.test(raw)) {
    return Buffer.from(raw, 'hex');
  }
  return crypto.scryptSync(raw, 'identitymonitor-salt-v1', 32);
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
