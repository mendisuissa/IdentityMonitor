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
// opts.gate: a promise every getEntity waits for; opts.failUpserts: number of upserts that fail first.
function loadWorkflowStore(stored = {}, opts = {}) {
  const upserts = [];
  let failsLeft = opts.failUpserts || 0;
  let readFailsLeft = opts.failReads || 0;
  let reads = 0;
  const audits = [];
  const fakes = {
    ...(opts.extraFakes || {}),
    '@azure/data-tables': {
      TableClient: {
        fromConnectionString: () => ({
          createTable: async () => {},
          getEntity: async (pk, rk) => {
            reads++;
            if (opts.gate) await opts.gate;
            if (readFailsLeft > 0) { readFailsLeft--; const e = new Error('server busy'); e.statusCode = 503; throw e; }
            if (!stored[rk]) { const e = new Error('nf'); e.statusCode = 404; throw e; }
            return stored[rk];
          },
          upsertEntity: async (entity) => {
            if (failsLeft > 0) { failsLeft--; throw new Error('table unavailable'); }
            upserts.push(entity);
          },
          listEntities: async function* () {}
        })
      }
    },
    './alertsStore': { getAll: () => opts.alerts || [], getOpen: () => opts.alerts || [] },
    './notificationCenterService': { enqueue: () => {}, list: () => [] },
    './auditLog': { log: (tenantId, action, details, actor) => audits.push({ tenantId, action, details, actor }) }
  };
  const origLoad = Module._load;
  Module._load = function (request, parent, isMain) {
    if (Object.prototype.hasOwnProperty.call(fakes, request)) return fakes[request];
    return origLoad.call(this, request, parent, isMain);
  };
  process.env.AZURE_STORAGE_CONNECTION_STRING = 'UseDevelopmentStorage=true';
  process.env.WORKFLOW_PERSIST_RETRY_MS = String(opts.retryMs || 10);
  const file = path.join(services, 'workflowStore.js');
  delete require.cache[require.resolve(file)];
  try {
    const store = require(file);
    let automation;
    if (opts.withAutomation) {
      fakes['./workflowStore'] = store;
      const af = path.join(services, 'automationService.js');
      delete require.cache[require.resolve(af)];
      automation = require(af);
    }
    return { store, automation, upserts, audits, reads: () => reads };
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

test('cache miss: two sync patches before the first read completes both survive', async () => {
  const stored = { a1: { owner: 'kept@contoso.com', caseStatus: 'triage', escalationLevel: 2 } };
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts, audits } = loadWorkflowStore(stored, { gate });
  store.patchAlertWorkflow('t1', 'a1', { note: 'first' }, 'system');
  store.patchAlertWorkflow('t1', 'a1', { escalationLevel: 3 }, 'system');
  store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'new@contoso.com' }, 'analyst@contoso.com');
  assert.strictEqual(upserts.length, 0, 'nothing written before the stored row is read');
  release();
  for (let i = 0; i < 10; i++) await settle();
  const last = upserts[upserts.length - 1];
  assert.strictEqual(last.note, 'first', 'first patch is not erased by the second');
  assert.strictEqual(last.escalationLevel, 3);
  assert.strictEqual(last.owner, 'new@contoso.com');
  assert.strictEqual(last.caseStatus, 'triage', 'stored field survives');
  assert.strictEqual(audits.length, 3);
  const wf = store.getAlertWorkflow('t1', 'a1');
  assert.deepStrictEqual([wf.note, wf.escalationLevel, wf.owner, wf.caseStatus], ['first', 3, 'new@contoso.com', 'triage']);
  assert.strictEqual(store.unpersistedCount(), 0);
});

test('cache miss: a queued patch that repeats an earlier queued value is a no-op', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts, audits } = loadWorkflowStore({ a1: { owner: 'o' } }, { gate });
  store.patchAlertWorkflow('t1', 'a1', { escalationLevel: 1 }, 'system');
  store.patchAlertWorkflow('t1', 'a1', { escalationLevel: 1 }, 'system');
  release();
  for (let i = 0; i < 10; i++) await settle();
  assert.strictEqual(audits.length, 1, 'second patch merged against the first, so nothing changed');
  assert.strictEqual(upserts[upserts.length - 1].escalationLevel, 1);
});

test('a failed upsert is retried even when the same patch is re-sent', async () => {
  const { store, upserts, audits } = loadWorkflowStore({}, { failUpserts: 1 });
  await store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'x@y.z' }, 'x@y.z');
  assert.strictEqual(upserts.length, 0, 'first write failed');
  assert.strictEqual(store.unpersistedCount(), 1, 'workflow is tracked as unpersisted');
  const again = store.patchAlertWorkflow('t1', 'a1', { owner: 'x@y.z' }, 'x@y.z');
  assert.strictEqual(again.owner, 'x@y.z');
  for (let i = 0; i < 5; i++) await settle();
  assert.strictEqual(upserts.length, 1, 'the no-op patch triggered the retry');
  assert.strictEqual(upserts[0].owner, 'x@y.z');
  assert.strictEqual(audits.length, 1, 'the retry is not logged again');
  assert.strictEqual(store.unpersistedCount(), 0);
});

test('a failed upsert is retried on its own with backoff', async () => {
  const { store, upserts } = loadWorkflowStore({}, { failUpserts: 2 });
  await store.patchAlertWorkflowAsync('t1', 'a1', { caseStatus: 'closed' }, 'system');
  assert.strictEqual(upserts.length, 0);
  for (let i = 0; i < 50 && upserts.length === 0; i++) await new Promise((r) => setTimeout(r, 10));
  assert.strictEqual(upserts.length, 1);
  assert.strictEqual(upserts[0].caseStatus, 'closed');
  assert.strictEqual(store.unpersistedCount(), 0);
});

test('warmCache does not replace an unpersisted workflow with the stored row', async () => {
  const { store } = loadWorkflowStore({}, { failUpserts: 100 });
  await store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'new@contoso.com' }, 'system');
  await store.warmCache('t1'); // fake listEntities yields nothing; must not clobber either way
  assert.strictEqual(store.getAlertWorkflow('t1', 'a1').owner, 'new@contoso.com');
});

const waitFor = async (cond) => { for (let i = 0; i < 100 && !cond(); i++) await new Promise((r) => setTimeout(r, 10)); };

test('a failed initial read keeps queued patches in order and retries the read', async () => {
  const stored = { a1: { owner: 'old@contoso.com', caseStatus: 'triage' } };
  const { store, upserts, audits, reads } = loadWorkflowStore(stored, { failReads: 2 });
  const view = await store.patchAlertWorkflowAsync('t1', 'a1', { owner: 'new@contoso.com' }, 'analyst@contoso.com');
  assert.strictEqual(view.owner, 'new@contoso.com', 'awaiting caller gets the optimistic result, not a hang');
  assert.strictEqual(store.unpersistedCount(), 1, 'the queued patch is counted as unpersisted');
  store.patchAlertWorkflow('t1', 'a1', { note: 'second' }, 'analyst@contoso.com');
  store.patchAlertWorkflow('t1', 'a1', { owner: 'newest@contoso.com' }, 'analyst@contoso.com');
  assert.strictEqual(store.getAlertWorkflow('t1', 'a1').owner, 'newest@contoso.com', 'sync read shows the optimistic view');
  assert.strictEqual(upserts.length, 0, 'nothing is written over the stored row before it is read');
  await waitFor(() => store.unpersistedCount() === 0);
  assert.strictEqual(reads(), 3, 'read retried with backoff, not once per patch');
  const last = upserts[upserts.length - 1];
  assert.deepStrictEqual([last.owner, last.note, last.caseStatus], ['newest@contoso.com', 'second', 'triage']);
  assert.deepStrictEqual(audits.map((a) => a.details.patch), [{ owner: 'new@contoso.com' }, { note: 'second' }, { owner: 'newest@contoso.com' }], 'applied in order');
});

test('cold cache: two comments both survive, along with the stored ones', async () => {
  const stored = { a1: { comments: JSON.stringify([{ id: 'c0', message: 'stored' }]) } };
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts } = loadWorkflowStore(stored, { gate });
  store.addComment('t1', 'a1', 'one', 'a@contoso.com');
  const optimistic = store.addComment('t1', 'a1', 'two @b@contoso.com', 'a@contoso.com');
  assert.deepStrictEqual(optimistic.comments.map((c) => c.message), ['one', 'two @b@contoso.com'], 'optimistic view chains queued updates');
  release();
  await waitFor(() => store.unpersistedCount() === 0);
  const comments = JSON.parse(upserts[upserts.length - 1].comments).map((c) => c.message);
  assert.deepStrictEqual(comments, ['stored', 'one', 'two @b@contoso.com']);
  assert.deepStrictEqual(JSON.parse(upserts[upserts.length - 1].mentions), ['b@contoso.com']);
});

test('cold cache: progressApproval right after a queued approval plan decides the step', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts } = loadWorkflowStore({ a1: { owner: 'o@contoso.com' } }, { gate });
  store.patchAlertWorkflow('t1', 'a1', { approvalSteps: [{ step: 1, role: 'lead', status: 'pending' }] }, 'system');
  const optimistic = store.progressApproval('t1', 'a1', 'approved', 'lead@contoso.com', 'ok');
  assert.strictEqual(optimistic.approvalStatus, 'approved', 'sync result is the optimistic decision');
  release();
  await waitFor(() => store.unpersistedCount() === 0);
  const last = upserts[upserts.length - 1];
  assert.strictEqual(JSON.parse(last.approvalSteps)[0].status, 'approved');
  assert.strictEqual(last.approvalStatus, 'approved');
  assert.strictEqual(last.caseStatus, 'ready_to_execute');
  assert.strictEqual(last.owner, 'o@contoso.com');
  assert.strictEqual(JSON.parse(last.approvalHistory).length, 1);
});

test('getCases SLA breach on a cold cache keeps stored owner and comments', async () => {
  const stored = { a1: { owner: 'kept@contoso.com', comments: JSON.stringify([{ id: 'c0', message: 'stored' }]) } };
  const alerts = [{ id: 'a1', severity: 'high', status: 'open', detectedAt: new Date().toISOString() }];
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts, audits } = loadWorkflowStore(stored, { gate, alerts });
  store.patchAlertWorkflow('t1', 'a1', { dueAt: new Date(Date.now() - 3600e3).toISOString() }, 'analyst@contoso.com');
  store.addComment('t1', 'a1', 'queued', 'analyst@contoso.com');
  const cases = store.getCases('t1');
  assert.ok(cases[0].slaBreachedAt, 'response still shows the breach');
  release();
  await waitFor(() => store.unpersistedCount() === 0);
  const last = upserts[upserts.length - 1];
  assert.strictEqual(last.owner, 'kept@contoso.com', 'stored owner survives');
  assert.deepStrictEqual(JSON.parse(last.comments).map((c) => c.message), ['stored', 'queued']);
  assert.ok(last.slaBreachedAt);
  assert.strictEqual(last.escalationLevel, 1);
  assert.strictEqual(audits.filter((a) => a.action === 'case.sla_breached').length, 1);
  const sla = audits.find((a) => a.action === 'workflow.updated' && a.details.fields);
  assert.deepStrictEqual(sla.details.fields, ['slaBreachedAt', 'escalationLevel'], 'only the SLA fields are patched');
});

test('getCases does not re-breach a case that the loaded state shows already breached', async () => {
  const past = new Date(Date.now() - 3600e3).toISOString();
  const stored = { a1: { dueAt: past, slaBreachedAt: past, escalationLevel: 2 } };
  const alerts = [{ id: 'a1', severity: 'high', status: 'open', detectedAt: past }];
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts, audits } = loadWorkflowStore(stored, { gate, alerts });
  store.addComment('t1', 'a1', 'x', 'a@contoso.com'); // queue so getCases sees an optimistic view
  store.getCases('t1');
  release();
  await waitFor(() => store.unpersistedCount() === 0);
  assert.strictEqual(audits.filter((a) => a.action === 'case.sla_breached').length, 0);
  assert.strictEqual(upserts[upserts.length - 1].escalationLevel, 2);
  assert.strictEqual(upserts[upserts.length - 1].slaBreachedAt, past);
});

test('updates submitted during read backoff resolve at once and stay queued', async () => {
  const { store, upserts } = loadWorkflowStore({ a1: { owner: 'o' } }, { failReads: 1, retryMs: 60000 });
  await store.patchAlertWorkflowAsync('t1', 'a1', { note: 'one' }, 'system');
  const timeout = new Promise((r) => setTimeout(() => r('timeout'), 300));
  const second = await Promise.race([store.patchAlertWorkflowAsync('t1', 'a1', { caseStatus: 'triage' }, 'auto-playbook'), timeout]);
  assert.notStrictEqual(second, 'timeout', 'awaiting caller is not held for the backoff');
  assert.deepStrictEqual([second.note, second.caseStatus], ['one', 'triage']);
  assert.strictEqual(store.unpersistedCount(), 1);
  assert.strictEqual(upserts.length, 0, 'still queued for the retried read');
});

test('updateAlertWorkflow appends to the loaded list on a cold cache', async () => {
  const stored = { a1: { automationActions: JSON.stringify([{ type: 'escalation', key: 'k0' }]) } };
  let release;
  const gate = new Promise((r) => { release = r; });
  const { store, upserts } = loadWorkflowStore(stored, { gate });
  const entry = { type: 'manual-execution', key: 'exec-1' };
  store.updateAlertWorkflow('t1', 'a1', (cur) => ({ caseStatus: 'executed', automationActions: [...cur.automationActions, entry] }), 'a@contoso.com');
  release();
  await waitFor(() => store.unpersistedCount() === 0);
  const last = upserts[upserts.length - 1];
  assert.deepStrictEqual(JSON.parse(last.automationActions).map((a) => a.key), ['k0', 'exec-1']);
  assert.strictEqual(last.caseStatus, 'executed');
});

test('isWorkflowLoaded starts the read and is true once loaded, also for a missing row', async () => {
  const { store } = loadWorkflowStore({ a1: { owner: 'o' } });
  assert.strictEqual(store.isWorkflowLoaded('t1', 'a1'), false);
  assert.strictEqual(store.isWorkflowLoaded('t1', 'missing'), false);
  await settle(); await settle();
  assert.strictEqual(store.isWorkflowLoaded('t1', 'a1'), true);
  assert.strictEqual(store.isWorkflowLoaded('t1', 'missing'), true);
  assert.strictEqual(store.getAlertWorkflow('t1', 'a1').owner, 'o');
});

test('automation sweep skips unloaded workflows and fills defaults without overwriting stored ones', async () => {
  const alerts = [{ id: 'a1', tenantId: 't1', severity: 'high', status: 'open', detectedAt: new Date().toISOString() }];
  const extraFakes = {
    './settingsService': { getSettings: () => ({ assignmentRules: { defaultOwner: 'default@contoso.com' }, runbooks: {} }) },
    './tenantRegistry': { getAllTenantIds: () => ['t1'] },
    './policyEngineService': { buildPolicyDecision: () => ({ requiresApproval: false }), getExecutionCheck: () => ({ canExecute: false, reason: 'r', state: 's' }) }
  };
  const stored = { a1: { owner: 'kept@contoso.com', caseStatus: 'triage' } };
  const { automation, upserts } = loadWorkflowStore(stored, { alerts, extraFakes, withAutomation: true });
  automation.runAutomationSweep('t1'); // cold: starts the read, writes nothing
  assert.strictEqual(upserts.length, 0);
  await settle(); await settle();
  automation.runAutomationSweep('t1');
  await settle();
  for (const u of upserts) assert.strictEqual(u.owner, 'kept@contoso.com', 'stored owner never replaced by the default owner');
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

function stampAt(ms) { return new Date(ms).toISOString().replace(/[:.]/g, '-'); }
function auditLines(from, to, pad = 0) {
  const out = [];
  for (let i = from; i < to; i++) out.push(JSON.stringify({ timestamp: new Date(1e12 + i).toISOString(), tenantId: 't1', action: 'x', i, pad: 'p'.repeat(pad) }));
  return out.join('\n') + '\n';
}

test('warmCache fills the recent window from the newest archives after rotation', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  fs.mkdirSync(path.join(dir, 'archive'));
  // oldest archive: must not be needed; newer archive is ~7 MB (bigger than the tail window)
  fs.writeFileSync(path.join(dir, 'archive', `t1.${stampAt(1e12)}.jsonl`), auditLines(0, 100));
  fs.writeFileSync(path.join(dir, 'archive', `t1.${stampAt(2e12)}.jsonl`), auditLines(100, 30100, 200));
  // another tenant whose id starts with "t1." must not be mixed in
  fs.writeFileSync(path.join(dir, 'archive', `t1.other.${stampAt(3e12)}.jsonl`), JSON.stringify({ timestamp: 'z', action: 'foreign', i: -1 }) + '\n');
  fs.writeFileSync(path.join(dir, 't1.jsonl'), auditLines(30100, 30110));
  const audit = loadAuditLog(dir);
  await audit.warmCache('t1');
  const got = audit.getLog('t1');
  assert.strictEqual(got.length, 2000);
  assert.strictEqual(got[0].i, 30109, 'newest live entry first');
  assert.strictEqual(got[9].i, 30100);
  assert.strictEqual(got[10].i, 30099, 'then the newest archived entries');
  assert.strictEqual(got[1999].i, 30109 - 1999);
  assert.ok(!got.some((e) => e.action === 'foreign'));
});

test('warmCache reads archives when the live file does not exist yet', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'audit-'));
  fs.mkdirSync(path.join(dir, 'archive'));
  fs.writeFileSync(path.join(dir, 'archive', `t1.${stampAt(1e12)}.jsonl`), auditLines(0, 5));
  fs.writeFileSync(path.join(dir, 'archive', `t1.${stampAt(2e12)}.jsonl`), auditLines(5, 8));
  const audit = loadAuditLog(dir);
  await audit.warmCache('t1');
  assert.deepStrictEqual(audit.getLog('t1').map((e) => e.i), [7, 6, 5, 4, 3, 2, 1, 0]);
  assert.strictEqual(fs.readdirSync(path.join(dir, 'archive')).length, 2, 'archives are only read');
});
