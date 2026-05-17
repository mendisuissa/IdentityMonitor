// azureTableSessionStore.js — express-session store backed by Azure Table Storage
// Replaces session-file-store to eliminate slow Azure SMB I/O on every request.
// Falls back gracefully if Azure Tables is not configured.

const { TableClient, AzureNamedKeyCredential, odata } = require('@azure/data-tables');
const session = require('express-session');

const TABLE_NAME = 'appsessions';

class AzureTableSessionStore extends session.Store {
  constructor(options = {}) {
    super();
    this.ttl = options.ttl || 86400; // seconds, default 24h
    this._client = null;
    this._ready = false;
    this._connStr = process.env.AZURE_STORAGE_CONNECTION_STRING;
    if (this._connStr) {
      this._init().catch(err => console.warn('[SessionStore] Init error:', err.message));
    }
  }

  async _init() {
    try {
      this._client = TableClient.fromConnectionString(this._connStr, TABLE_NAME);
      await this._client.createTable();
      this._ready = true;
      console.log('[SessionStore] Azure Table session store ready');
    } catch (err) {
      if (err.statusCode === 409) {
        // Table already exists — that's fine
        this._ready = true;
        console.log('[SessionStore] Azure Table session store ready (existing table)');
      } else {
        console.warn('[SessionStore] Could not create table:', err.message);
      }
    }
  }

  _expiry(sess) {
    if (sess?.cookie?.expires) return new Date(sess.cookie.expires).getTime();
    return Date.now() + this.ttl * 1000;
  }

  get(sid, cb) {
    if (!this._ready) return cb(null, null);
    this._client.getEntity('session', sid)
      .then(entity => {
        if (!entity) return cb(null, null);
        if (entity.expiresAt && Date.now() > Number(entity.expiresAt)) {
          // Expired — destroy silently
          this.destroy(sid, () => {});
          return cb(null, null);
        }
        let data;
        try { data = JSON.parse(entity.data); } catch { return cb(null, null); }
        cb(null, data);
      })
      .catch(err => {
        if (err.statusCode === 404) return cb(null, null);
        console.warn('[SessionStore] get error:', err.message);
        cb(null, null); // degrade gracefully — don't block the request
      });
  }

  set(sid, sess, cb) {
    if (!this._ready) return cb && cb();
    const expiresAt = this._expiry(sess);
    const entity = {
      partitionKey: 'session',
      rowKey: sid,
      data: JSON.stringify(sess),
      expiresAt: String(expiresAt),
    };
    this._client.upsertEntity(entity, 'Replace')
      .then(() => cb && cb())
      .catch(err => {
        console.warn('[SessionStore] set error:', err.message);
        cb && cb(); // fail silently
      });
  }

  destroy(sid, cb) {
    if (!this._ready) return cb && cb();
    this._client.deleteEntity('session', sid)
      .then(() => cb && cb())
      .catch(err => {
        if (err.statusCode !== 404) console.warn('[SessionStore] destroy error:', err.message);
        cb && cb();
      });
  }

  touch(sid, sess, cb) {
    // Just re-upsert with updated expiry
    this.set(sid, sess, cb);
  }
}

module.exports = AzureTableSessionStore;
