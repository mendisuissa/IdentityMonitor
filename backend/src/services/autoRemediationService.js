/**
 * autoRemediationService.js
 *
 * Runs on a cron schedule, scans every registered tenant for open CVEs,
 * plans + executes remediation automatically, saves results to history,
 * and sends a Telegram summary.
 *
 * Environment variables:
 *   AUTO_REMEDIATION_ENABLED=true        — must be explicitly enabled
 *   AUTO_REMEDIATION_INTERVAL_MINUTES=60 — how often to run (default 60)
 *   AUTO_REMEDIATION_MAX_PER_RUN=10      — max CVEs to remediate per tenant per run
 */

const { listTenantVulnerabilities, enrichTenantVulnerability } = require('./tenantDefenderClient');
const { enrichFinding, classifyFinding }                       = require('./remediationCatalog');
const { executeApplicationRemediation, getExternalHealth }     = require('./webappExecutionClient');
const { executeNativeRemediation }                             = require('./nativeRemediationExecutor');
const { saveRemediationRecord, getRecentSuccessForCve, getRecentAttemptForCve } = require('./remediationHistoryStore');
const { sendRemediationNotification }                          = require('./emailService');
const tenantRegistry                                           = require('./tenantRegistry');
const telegramService                                          = require('./telegramService');
const { fmtTime }                                              = require('./telegramService');
const tableStorage                                             = require('./tableStorage');

const ENABLED           = () => process.env.AUTO_REMEDIATION_ENABLED === 'true';
const INTERVAL_MS       = () => Math.max(5, Number(process.env.AUTO_REMEDIATION_INTERVAL_MINUTES || 60)) * 60 * 1000;
const MAX_PER_RUN       = () => Math.max(1, Math.min(Number(process.env.AUTO_REMEDIATION_MAX_PER_RUN || 10), 50));
const APPROVAL_TIMEOUT  = () => Math.max(1, Number(process.env.AUTO_REMEDIATION_APPROVAL_MINUTES || 5)) * 60 * 1000;
const REQUIRE_APPROVAL  = () => process.env.AUTO_REMEDIATION_REQUIRE_APPROVAL !== 'false'; // default true

let _timer   = null;
let _running = false;

// Persisted (tableStorage.getSeenCves/saveSeenCves) — tracks which CVE IDs we've
// already seen per tenant, for new-CVE Telegram alerts. Was an in-memory Map here
// until 2026-08-11: it reset to empty on every app restart, and the first scan
// after any restart silently re-baselines without alerting (see remediateTenant
// below) — during the stretch where every deploy attempt hit a Kudu conflict
// (2026-07-15 to 2026-08-10), that meant new-CVE alerts went silent for weeks.

// ── Run history — exposed to supervisor via /api/health-deep ─────────────────
const _runHistory = [];   // last 20 runs, newest first
const MAX_HISTORY = 20;

function _recordRun(summaries) {
  const rec = {
    runAt:        new Date().toISOString(),
    totalSuccess: summaries.reduce((a, s) => a + (s.success || 0), 0),
    totalFailed:  summaries.reduce((a, s) => a + (s.failed  || 0), 0),
    totalSkipped: summaries.reduce((a, s) => a + (s.skipped || 0), 0),
    errors:       summaries.filter(s => s.error).map(s => ({ tenantId: s.tenantId, error: s.error })),
    failedActions: summaries.flatMap(s =>
      (s.actions || []).filter(a => a.status === 'failed').map(a => ({
        tenantId:    s.tenantId,
        cveId:       a.cveId,
        productName: a.productName,
        message:     a.message,
      }))
    ).slice(0, 20),
  };
  _runHistory.unshift(rec);
  if (_runHistory.length > MAX_HISTORY) _runHistory.pop();
  return rec;
}

function getRunStats() {
  const last24h = Date.now() - 24 * 60 * 60 * 1000;
  const recent  = _runHistory.filter(r => new Date(r.runAt).getTime() > last24h);
  return {
    lastRunAt:       _runHistory[0]?.runAt || null,
    runsLast24h:     recent.length,
    failedLast24h:   recent.reduce((a, r) => a + r.totalFailed, 0),
    successLast24h:  recent.reduce((a, r) => a + r.totalSuccess, 0),
    recentErrors:    recent.flatMap(r => r.errors).slice(0, 5),
    recentFailedActions: recent.flatMap(r => r.failedActions).slice(0, 10),
    history:         _runHistory.slice(0, 5),
  };
}

// ── Severity sort order ───────────────────────────────────────────────────────

const SEV_ORDER = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
function sevRank(s) { return SEV_ORDER[String(s || '').toLowerCase()] ?? 4; }

// ── Garbage product name detection ───────────────────────────────────────────
// Defender TVM sometimes populates productName with fragment text scraped from
// the CVE description instead of the actual software name. Detect and skip these.

const GARBAGE_PHRASES = [
  'is available at this time',
  'a security update',
  'an update',
  'this update',
  'the update',
  'is not available',
  'has been released',
  'not applicable',
  'n/a',
];

function isGarbageProductName(name) {
  if (!name || name.trim().length < 2) return true;
  const n = name.toLowerCase().trim();
  // Contains sentence-like filler phrases
  if (GARBAGE_PHRASES.some(p => n.includes(p))) return true;
  // CVE/TVM ID used as product name instead of actual software name
  if (/^(cve|tvm)-\d{4}-\d+$/i.test(name.trim())) return true;
  // Looks like a sentence (contains 4+ words and common verbs) — not a product name
  const words = n.split(/\s+/);
  if (words.length >= 4 && /\b(is|are|was|has|have|not|this|that|the|an|a)\b/.test(n)) return true;
  return false;
}

// ── Per-tenant remediation ────────────────────────────────────────────────────

async function remediateTenant(tenantId, options = {}) {
  const forceRemediate = options.forceRemediate === true;
  const summary = {
    tenantId,
    total:       0,
    success:     0,
    failed:      0,
    skipped:     0,
    unsupported: 0,
    actions:     [],
  };

  let vulns;
  try {
    vulns = await listTenantVulnerabilities(tenantId, 200);
  } catch (err) {
    console.error(`[AutoRemediation] ${tenantId} — failed to list CVEs:`, err.message);
    summary.error = err.message;
    return summary;
  }

  // ── Detect new CVEs vs last run ──────────────────────────────────────────
  {
    const currentIds = new Set(vulns.map(v => (v.cveId || v.id || '').toUpperCase()).filter(Boolean));
    const seenIds    = await tableStorage.getSeenCves(tenantId).catch(err => {
      console.error(`[AutoRemediation] ${tenantId} — getSeenCves failed, treating as first run:`, err.message);
      return null;
    });
    let newOnes = [];
    if (seenIds) {
      newOnes = vulns.filter(v => {
        const id = (v.cveId || v.id || '').toUpperCase();
        return id && !seenIds.has(id);
      });
    } else {
      console.log(`[AutoRemediation] ${tenantId} — first scan ever for this tenant, seeding baseline of ${currentIds.size} CVE(s) without alerting`);
    }
    // Persist the seen set BEFORE marking the alert timestamp — saveSeenCves
    // writes in 'Replace' mode (see below) and would otherwise wipe lastAlertAt
    // if it ran second; markCveAlertSent uses 'Merge' so it layers on safely.
    await tableStorage.saveSeenCves(tenantId, currentIds).catch(err =>
      console.error(`[AutoRemediation] ${tenantId} — saveSeenCves failed:`, err.message)
    );
    if (newOnes.length > 0) {
      console.log(`[AutoRemediation] ${tenantId} — ${newOnes.length} new CVE(s) detected, sending Telegram alert`);
      telegramService.sendNewCveAlert(tenantId, newOnes).catch(() => {});
      await tableStorage.markCveAlertSent(tenantId).catch(err =>
        console.error(`[AutoRemediation] ${tenantId} — markCveAlertSent failed:`, err.message)
      );
    }
  }

  // Sort: Critical first, then High, Medium, Low
  const sorted = [...vulns].sort((a, b) => sevRank(a.severity) - sevRank(b.severity));
  const maxRun = MAX_PER_RUN();
  let actioned = 0;

  for (const vuln of sorted) {
    if (actioned >= maxRun) break;

    const cveId      = vuln.cveId || vuln.id || '';
    const enriched   = enrichFinding(vuln);
    const category   = enriched.classification?.type || vuln.category || 'unknown';

    summary.total++;

    // ── 0. Garbage product name — skip finding, don't waste a remediation slot ─
    const rawProductName = enriched.productName || vuln.productName || vuln.softwareName || '';
    if (isGarbageProductName(rawProductName)) {
      console.log(`[AutoRemediation] ${tenantId} ${cveId} — skipped (garbage product name: "${rawProductName}")`);
      summary.skipped++;
      continue;
    }

    console.log(`[AutoRemediation] ${tenantId} ${cveId || '(no-id)'} product="${rawProductName}" sev=${vuln.severity} → category=${category}`);

    // ── 1. Unsupported platform — just record, no action ─────────────────────
    if (category === 'unsupported-platform') {
      summary.unsupported++;
      await saveRemediationRecord({
        tenantId, cveId,
        productName: enriched.productName || '',
        category,
        severity: vuln.severity || '',
        status: 'unsupported',
        executor: 'auto',
        triggeredBy: 'cron',
        message: 'Non-Windows platform — automated remediation not available.',
      }).catch(() => {});
      continue;
    }

    // ── 2. Already fixed recently — skip (bypassed when forceRemediate=true) ──
    if (cveId && !forceRemediate) {
      const recent = await getRecentSuccessForCve(tenantId, cveId, 24).catch(() => null);
      if (recent) {
        console.log(`[AutoRemediation] ${tenantId} ${cveId} — skipped (fixed within 24h)`);
        summary.skipped++;
        continue;
      }
      // Also skip if attempted within 6h — prevents hourly spam on permanently-failing CVEs
      const recentAttempt = await getRecentAttemptForCve(tenantId, cveId, 6).catch(() => null);
      if (recentAttempt) {
        console.log(`[AutoRemediation] ${tenantId} ${cveId} — skipped (attempted within 6h, status=${recentAttempt.status})`);
        summary.skipped++;
        continue;
      }
    }

    actioned++;

    // ── 3. Approval gate ──────────────────────────────────────────────────
    // Was gated to Critical severity only, regardless of REQUIRE_APPROVAL()'s
    // own setting — found live (2026-08-11) via a company-wide sweep for
    // unguarded-automation bugs: AUTO_REMEDIATION_REQUIRE_APPROVAL defaults
    // to true (the tenant's explicit opt-in to "don't auto-remediate without
    // a human check"), yet High/Medium/Low CVEs — 3 of 4 severity tiers —
    // silently bypassed that setting entirely and deployed to the whole
    // fleet unattended, based on Defender TVM data this same file's own
    // isGarbageProductName() admits is sometimes dirty. Now honors the
    // setting for every severity, matching what its name promises.
    if (REQUIRE_APPROVAL()) {
      console.log(`[AutoRemediation] ${tenantId} ${cveId} — ${vuln.severity || 'unknown'} severity CVE, requesting Telegram approval`);
      let decision = 'approved';
      try {
        decision = await telegramService.requestCveApproval(tenantId, cveId, enriched, APPROVAL_TIMEOUT());
      } catch (err) {
        console.error(`[AutoRemediation] Approval request failed for ${cveId}:`, err.message);
        decision = 'approved'; // fail-open
      }
      if (decision === 'skipped') {
        summary.skipped++;
        summary.total++;
        await saveRemediationRecord({
          tenantId, cveId,
          productName: enriched.productName || '',
          category,
          severity: vuln.severity || '',
          status: 'skipped',
          executor: 'auto',
          triggeredBy: 'cron',
          message: 'Skipped by admin via Telegram approval gate.',
        }).catch(() => {});
        continue;
      }
    }

    // ── 4. Deep-enrich CVE before executing (gets affectedMachines, WingetId, etc.)
    // 5-second cap so a slow Defender enrichment call doesn't stall the whole run.
    let enrichedDeep = enriched;
    try {
      if (cveId.toUpperCase().startsWith('CVE-')) {
        const ENRICH_TIMEOUT_MS = 5000;
        const deep = await Promise.race([
          enrichTenantVulnerability(tenantId, cveId),
          new Promise((_, rej) => setTimeout(() => rej(new Error('enrich-timeout')), ENRICH_TIMEOUT_MS)),
        ]);
        if (deep) enrichedDeep = { ...enriched, ...deep };
      }
    } catch (_) { /* enrichment is best-effort */ }

    // ── 5. Execute based on category ─────────────────────────────────────────
    let status  = 'failed';
    let message = '';
    let result  = {};

    try {
      if (category === 'application') {
        // Check webapp health first
        const health = await getExternalHealth();
        if (!health.ok) {
          status  = 'skipped';
          message = `Webapp unreachable (${health.error || 'health check failed'}) — will retry next run.`;
          summary.skipped++;
        } else {
          result  = await executeApplicationRemediation({
            tenantId,
            approvalId: `auto-${cveId}-${Date.now()}`,
            finding: enrichedDeep,
            devices: [],
            plan: { executor: 'webapp' },
            options: {
              deployToAllDevices:  true,
              assignToAllDevices:  true,
              suggestedWingetId:   enrichedDeep.suggestedWingetId || undefined,
            },
          });
          const ok = result?.ok !== false && result?.status !== 'failed';
          status  = ok ? 'success' : 'failed';
          message = result?.message || (ok ? 'Deployed via WinGet to All Devices.' : 'Deployment failed.');
          if (ok) summary.success++; else summary.failed++;
        }

      } else if (category === 'windows-update' || category === 'platform') {
        const affectedMachines = enrichedDeep.affectedMachines || [];
        if (!affectedMachines.length) {
          // WUfB Deployment Service requires device IDs — skip until enrichment resolves them
          status  = 'skipped';
          message = `Windows Update skipped — no affected device names available for ${cveId || 'this finding'}. Will retry when device data is enriched.`;
          summary.skipped++;
        } else {
          result  = await executeNativeRemediation({
            tenantId,
            finding: enrichedDeep,
            classification: enrichedDeep.classification || { type: 'windows-update', family: 'platform' },
            options: {
              updateType:          'security',
              rebootBehavior:      'ifRequired',
              deviceIds:           [],
              affectedDeviceNames: affectedMachines,
            },
          });
          const ok = result?.ok !== false;
          status  = ok ? 'success' : 'failed';
          message = result?.message || (ok ? 'Windows Update deployed.' : 'Windows Update failed.');
          if (ok) summary.success++; else summary.failed++;
        }

      } else {
        // identity, intune-policy, script — not auto-remediable yet
        status  = 'skipped';
        message = `Category '${category}' requires manual review.`;
        summary.skipped++;
      }

    } catch (execErr) {
      message = execErr?.message || 'Execution error.';
      result  = { error: message };
      // "No WinGet package found" is a permanent lookup miss — not a retriable failure.
      // Mark as unsupported so it doesn't trigger Telegram alerts on every run.
      if (message.includes('No WinGet package found')) {
        status = 'unsupported';
        summary.unsupported++;
        console.log(`[AutoRemediation] ${tenantId} ${cveId} — unsupported (WinGet lookup miss): ${message}`);
      } else {
        status = 'failed';
        summary.failed++;
        console.error(`[AutoRemediation] ${tenantId} ${cveId} execute error:`, message);
      }
    }

    const action = {
      cveId,
      productName: enrichedDeep.productName || '',
      severity:    vuln.severity || '',
      category,
      status,
      message,
    };
    summary.actions.push(action);

    const histRecord = await saveRemediationRecord({
      tenantId,
      ...action,
      executor:    'auto',
      triggeredBy: 'cron',
      result,
    }).catch(() => null);

    // Send email notification for successful remediations
    if (histRecord && (status === 'success' || status === 'failed')) {
      sendRemediationNotification({ ...histRecord, triggeredBy: 'auto-cron' }, tenantId).catch(() => {});
    }

    // Small pause between CVEs to avoid hammering APIs
    await new Promise(r => setTimeout(r, 500));
  }

  return summary;
}

// ── Full run across all tenants ───────────────────────────────────────────────

async function runAutoRemediation() {
  if (_running) {
    console.log('[AutoRemediation] Previous run still in progress — skipping.');
    return;
  }
  _running = true;
  const startedAt = new Date().toISOString();
  console.log(`[AutoRemediation] Run started at ${startedAt}`);

  // Use async getAllTenants() so Azure-persisted profiles survive backend restarts.
  // Fall back to sync getAllTenantIds() if async lookup fails.
  let tenantIds;
  try {
    const tenants = await tenantRegistry.getAllTenants();
    tenantIds = tenants.map(t => t.tenantId).filter(Boolean);
  } catch (_) {
    tenantIds = tenantRegistry.getAllTenantIds();
  }
  if (!tenantIds.length) {
    console.log('[AutoRemediation] No active tenants — nothing to do.');
    _running = false;
    return;
  }

  const allSummaries = [];

  for (const tenantId of tenantIds) {
    try {
      const summary = await remediateTenant(tenantId);
      allSummaries.push(summary);
    } catch (err) {
      console.error(`[AutoRemediation] Tenant ${tenantId} run failed:`, err.message);
      allSummaries.push({ tenantId, error: err.message, total: 0, success: 0, failed: 0, skipped: 0, unsupported: 0, actions: [] });
    }
  }

  _running = false;

  _recordRun(allSummaries);

  const totalSuccess = allSummaries.reduce((a, s) => a + s.success, 0);
  const totalFailed  = allSummaries.reduce((a, s) => a + s.failed, 0);
  const totalSkipped = allSummaries.reduce((a, s) => a + s.skipped, 0);
  const totalUnsup   = allSummaries.reduce((a, s) => a + s.unsupported, 0);

  console.log(`[AutoRemediation] Run complete — ✅ ${totalSuccess} success, ❌ ${totalFailed} failed, ⏭ ${totalSkipped} skipped, 🚫 ${totalUnsup} unsupported`);

  // ── Telegram notification (uses settings-based credentials with env fallback) ──
  if (totalSuccess > 0 || totalFailed > 0) {
    const firstTenant = allSummaries[0]?.tenantId;
    try {
      let msg = `🤖 *Auto\\-Remediation Run*\n\n`;
      msg += `📅 ${escMd(fmtTime(new Date().toISOString()))}\n`;
      msg += `✅ Success: *${totalSuccess}*  ❌ Failed: *${totalFailed}*  ⏭ Skipped: *${totalSkipped}*\n\n`;

      for (const s of allSummaries) {
        if (!s.actions?.length) continue;
        msg += `🏢 *${escMd(s.tenantId.substring(0, 8))}…*\n`;
        for (const a of s.actions.slice(0, 5)) {
          const icon = a.status === 'success' ? '✅' : a.status === 'skipped' ? '⏭' : '❌';
          msg += `  ${icon} ${escMd(a.cveId)} · ${escMd(a.productName || a.category)}\n`;
          if (a.status === 'failed' && a.message) {
            const errSnippet = String(a.message).slice(0, 120);
            msg += `     _${escMd(errSnippet)}_\n`;
          }
        }
        if (s.actions.length > 5) msg += `  \\.\\.\\. and ${s.actions.length - 5} more\n`;
        msg += '\n';
      }

      await telegramService.sendMessageForTenant(firstTenant, msg);
    } catch (_) { /* non-fatal */ }
  }

  return allSummaries;
}

// ── Manual trigger — runs for a single tenant, bypasses _running lock ────────
async function runForTenant(tenantId, options = {}) {
  if (!tenantId) throw new Error('tenantId is required');
  const forceRemediate = options.forceRemediate !== false; // default true for manual triggers
  console.log(`[AutoRemediation] Manual trigger for tenant ${tenantId} forceRemediate=${forceRemediate}`);
  const summary = await remediateTenant(tenantId, { forceRemediate });
  const summaries = [summary];

  // ── Telegram notification (uses settings-based credentials with env fallback) ──
  if (summary.success > 0 || summary.failed > 0) {
    try {
      let msg = `🤖 *Manual Remediation Run*\n\n`;
      msg += `📅 ${escMd(fmtTime(new Date().toISOString()))}\n`;
      msg += `✅ Success: *${summary.success}*  ❌ Failed: *${summary.failed}*  ⏭ Skipped: *${summary.skipped}*\n\n`;
      msg += `🏢 *${escMd(tenantId.substring(0, 8))}…*\n`;
      for (const a of (summary.actions || []).slice(0, 10)) {
        const icon = a.status === 'success' ? '✅' : a.status === 'skipped' ? '⏭' : '❌';
        msg += `  ${icon} ${escMd(a.cveId)} · ${escMd(a.productName || a.category)}\n`;
      }
      if ((summary.actions?.length || 0) > 10) msg += `  \\.\\.\\. and ${summary.actions.length - 10} more\n`;
      await telegramService.sendMessageForTenant(tenantId, msg);
    } catch (_) { /* non-fatal */ }
  }

  return summaries;
}

function escMd(str) {
  return String(str || '').replace(/[_*[\]()~`>#+=|{}.!\\-]/g, '\\$&');
}

// ── Lifecycle ─────────────────────────────────────────────────────────────────

function start() {
  if (!ENABLED()) {
    console.log('[AutoRemediation] Disabled (AUTO_REMEDIATION_ENABLED != true)');
    return;
  }
  if (_timer) return; // already running

  const intervalMs = INTERVAL_MS();
  console.log(`[AutoRemediation] Enabled — running every ${intervalMs / 60000} minutes`);

  // First run after a warmup delay — prevents back-to-back runs on App Service restarts
  const warmupMs = Math.min(intervalMs, 5 * 60 * 1000); // 5 min or one interval, whichever is shorter
  console.log(`[AutoRemediation] First run in ${warmupMs / 60000} minutes`);
  setTimeout(() => runAutoRemediation().catch(console.error), warmupMs);

  _timer = setInterval(() => runAutoRemediation().catch(console.error), intervalMs);
}

function stop() {
  if (_timer) { clearInterval(_timer); _timer = null; }
}

function isEnabled() { return ENABLED(); }

module.exports = { start, stop, runAutoRemediation, runForTenant, isEnabled, getRunStats };
