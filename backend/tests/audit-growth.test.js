// Regression tests for the audit-log growth that filled /home/audit (9.4 GB, Nov 2026).
// Run: node --test backend/tests/audit-growth.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const Module = require('module');

const services = path.join(__dirname, '../src/services');

// ── workflowStore with fake Azure Table, alerts store, notifications and audit log ──
function loadWorkflowStore(stored = {}) {
  const upserts = [];
  const audits = [];
  const fakes = {
    '@azure/data-tables': {
      TableClient: {
        fromConnectionString: () => ({
          createTable: async () => {},
          getEntity: async (pk, rk) => {
            if (!stored[rk]) { const e = new Error('nf'); e.statusCode = 404; throw e; }
            return stored[rk];
          },
          upsertEntity: async (entity) => { upserts.push(entity); },
          listEntities: async function* () {}
        })
      }
    },
    './alertsStore': { getAll: () => [], getOpen: () => [] },
    './notificationCenterService': { enqueue: () => {}, list: () => [] },
    './auditLog': { log: (tenantId, action, details, actor) => audits.push({ tenantId, action, details, actor }) }
  };
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(fakes, request)) return fakes[request];
    return origLoad.call(this, request, parent, isMain);
  };
  process.env.AZURE_STORAGE_CONNECTION_STRING = 'UseDevelopmentStorage=true';
  const file = path.join(services, 'workflowStore.js');
  delete require.cache[require.resolve(file)];
  try {
    return { store: require(file), upserts, audits };
  } finally {
    Module._load = origLoad;
  }
}

const settle = () => new Promise((r) => setImmediate(r));

test('cache hit: a patch that changes nothing is neither written nor logged', async () => {
  const { store, upserts, audits } = loadWorkflowStore();
  await store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'x@y.z' }, 'x@y.z');
  upserts.length = 0; audits.length = 0;
  store.patchAlertWorkflow('t1', 'a1', { owner: 'x@y.z', isOverdue: false }, 'system');
  await settle();
  assert.strictEqual(upserts.length, 0);
  assert.strictEqual(audits.length, 0);
});

test('cache hit: a real system change is written once and logged once, with field names only', async () => {
  const { store, upserts, audits } = loadWorkflowStore();
  await store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'x@y.z' }, 'x@y.z');
  upserts.length = 0; audits.length = 0;
  const actions = [{ type: 'escalation', key: 'esc-a1-1', detail: 'x'.repeat(500) }];
  const next = store.patchAlertWorkflow('t1', 'a1', { escalationLevel: 1, automationActions: actions }, 'system');
  await settle();
  assert.strictEqual(next.escalationLevel, 1);
  assert.strictEqual(upserts.length, 1);
  assert.strictEqual(audits.length, 1);
  assert.deepStrictEqual(audits[0].details, { alertId: 'a1', fields: ['escalationLevel', 'automationActions'] });
});

test('a human change keeps the full patch in the audit entry', async () => {
  const { store, audits } = loadWorkflowStore();
  await store.patchAlertWorkflowAsync('t1', 'a1', { caseStatus: 'closed' }, 'analyst@contoso.com');
  assert.strictEqual(audits.length, 1);
  assert.deepStrictEqual(audits[0].details, { alertId: 'a1', patch: { caseStatus: 'closed' } });
});

test('cache miss: merges into the stored workflow, never into defaults, and skips a no-op', async () => {
  const stored = { a1: { owner: 'kept@contoso.com', caseStatus: 'triage', escalationLevel: 3, notifications: '[{"key":"n1"}]' } };
  const { store, upserts, audits } = loadWorkflowStore(stored);
  store.patchAlertWorkflow('t1', 'a1', { escalationLevel: 3 }, 'system');
  await settle(); await settle();
  assert.strictEqual(upserts.length, 0, 'unchanged stored value is not rewritten');
  assert.strictEqual(audits.length, 0);

  store.patchAlertWorkflow('t1', 'a2', {}, 'system'); // unknown alert, empty patch: nothing to do
  await settle(); await settle();
  assert.strictEqual(upserts.length, 0);

  const { store: s2, upserts: u2 } = loadWorkflowStore(stored);
  s2.patchAlertWorkflow('t1', 'a1', { note: 'n' }, 'system');
  await settle(); await settle();
  assert.strictEqual(u2.length, 1);
  assert.strictEqual(u2[0].owner, 'kept@contoso.com', 'stored owner survives the merge');
  assert.strictEqual(u2[0].notifications, '[{"key":"n1"}]');
});

// ── auditLog: tail-only warm-up and rotation ──
function loadAuditLog(dir, rotateBytes) {
  process.env.AUDIT_DIR = dir;
  if (rotateBytes) process.env.AUDIT_ROTATE_BYTES = String(rotateBytes); else delete process.env.AUDIT_ROTATE_BYTES;
  const file = path.join(services, 'auditLog.js');
  delete require.cache[require.resolve(file)];
  return require(file);
}

test('warmCache reads only the tail and still returns the newest entries', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  const lines = [];
  for (let i = 0; i < 30000; i++) lines.push(JSON.stringify({ timestamp: new Date(1e12 + i).toISOString(), tenantId: 't1', action: 'x', i, pad: 'p'.repeat(200) }));
  fs.writeFileSync(path.join(dir, 't1.jsonl'), lines.join('\n') + '\n'); // ~7 MB, larger than the tail window
  const audit = loadAuditLog(dir);
  await audit.warmCache('t1');
  const got = audit.getLog('t1');
  assert.strictEqual(got.length, 2000);
  assert.strictEqual(got[0].i, 29999, 'newest first');
  assert.ok(got.every((e) => typeof e.i === 'number'), 'no partial line parsed');
});

test('the live file rotates into archive/ past the size limit, and nothing is deleted', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  fs.writeFileSync(path.join(dir, 't1.jsonl'), 'x'.repeat(2048) + '\n');
  const audit = loadAuditLog(dir, 1024);
  audit.log('t1', 'admin.login', {}, 'a@b.c');
  for (let i = 0; i < 50 && !fs.existsSync(path.join(dir, 'archive')); i++) await new Promise((r) => setTimeout(r, 20));
  for (let i = 0; i < 50 && fs.existsSync(path.join(dir, 't1.jsonl')); i++) await new Promise((r) => setTimeout(r, 20));
  const archived = fs.readdirSync(path.join(dir, 'archive'));
  assert.strictEqual(archived.length, 1);
  assert.match(archived[0], /^t1\..+\.jsonl$/);
  assert.ok(fs.readFileSync(path.join(dir, 'archive', archived[0]), 'utf8').includes('admin.login'));
  assert.ok(!fs.readdirSync(dir).some((n) => n.endsWith('.jsonl')), 'no tenant-looking file left behind by rotation');
});
