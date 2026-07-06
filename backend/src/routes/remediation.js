const express = require('express');
const { classifyFinding, enrichFinding } = require('../services/remediationCatalog');
const {
  getExternalHealth,
  resolveApplicationRemediation,
  executeApplicationRemediation
} = require('../services/webappExecutionClient');
const {
  planNativeRemediation,
  executeNativeRemediation,
  executeImmediateWindowsUpdate,
  listTenantConfigurationPolicies,
  listTenantDeviceScripts
} = require('../services/nativeRemediationExecutor');
const { BUILT_IN_POLICY_TEMPLATES, getRecommendedPolicyTemplates } = require('../services/builtInPolicyTemplates');
const { saveRemediationRecord, getRemediationHistory, getRemediationStats } = require('../services/remediationHistoryStore');
const { sendRemediationNotification } = require('../services/emailService');
const autoRemediationService = require('../services/autoRemediationService');

const router = express.Router();

// ── In-memory job store for async auto-remediation runs ──────────────────────
// Key: jobId (string)  Value: { status: 'running'|'completed'|'error', summaries?, error? }
const _autoRemJobs = new Map();
function _cleanupJob(jobId) {
  setTimeout(() => _autoRemJobs.delete(jobId), 15 * 60 * 1000); // expire after 15 min
}

function getTenantIdFromRequest(req) {
  const sessionTenantId = req.session?.tenant?.tenantId || null;
  const requestedTenantId = req.body?.tenantId || null;
  if (!sessionTenantId) {
    const err = new Error('No authenticated tenant session was found.');
    err.status = 401;
    throw err;
  }
  if (requestedTenantId && requestedTenantId !== sessionTenantId) {
    const err = new Error('Cross-tenant remediation requests are not allowed.');
    err.status = 403;
    throw err;
  }
  return sessionTenantId;
}


router.get('/catalog/intune-policies', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const finding = enrichFinding({
      cveId: req.query?.cveId || null,
      productName: req.query?.productName || null,
      displayProductName: req.query?.displayProductName || null,
      category: req.query?.category || null,
      description: req.query?.description || null,
      classification: {
        type: req.query?.classificationType || null,
        family: req.query?.classificationFamily || null,
      },
    });
    const recommended = getRecommendedPolicyTemplates(finding);
    const tenantPolicies = await listTenantConfigurationPolicies(tenantId);
    res.json({
      ok: true,
      tenantId,
      recommended,
      builtIn: BUILT_IN_POLICY_TEMPLATES,
      tenantPolicies,
    });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.get('/catalog/intune-scripts', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const scripts = await listTenantDeviceScripts(tenantId);
    res.json({ ok: true, tenantId, scripts });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.get('/health', async (_req, res) => {
  const external = await getExternalHealth();
  res.json({
    ok: true,
    service: 'identity-remediation-orchestrator',
    graphConfigured: !!process.env.CLIENT_ID && !!process.env.CLIENT_SECRET,
    external
  });
});

// Debug: resolve a finding against the Webapp — call from browser to diagnose
// GET /api/remediation/debug-resolve?productName=microsoft_edge&publisher=microsoft
router.get('/debug-resolve', async (req, res) => {
  try {
    const { resolveApplicationRemediation } = require('../services/webappExecutionClient');
    const { enrichFinding } = require('../services/remediationCatalog');
    const finding = enrichFinding({
      productName: req.query.productName || null,
      softwareName: req.query.softwareName || null,
      publisher: req.query.publisher || null,
      description: req.query.description || null,
      category: req.query.category || 'application',
      cveId: req.query.cveId || null,
    });
    const result = await resolveApplicationRemediation(finding);
    return res.json({ ok: true, finding, result });
  } catch (err) {
    return res.json({ ok: false, error: err?.message, status: err?.status, details: err?.details });
  }
});

router.post('/plan', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { finding = {}, options = {} } = req.body || {};
    const enrichedFinding = enrichFinding(finding);
    const classification = enrichedFinding.classification || classifyFinding(enrichedFinding);

    if (classification.type === 'unsupported-platform') {
      const platformHint = (() => {
        const p = String(enrichedFinding.productName || '').toLowerCase();
        const pub = String(enrichedFinding.publisher || '').toLowerCase();
        if (/ubuntu|debian|rhel|centos|fedora|alpine|opensuse|linux/.test(p) || ['canonical','debian','red hat','redhat'].some(x => pub.includes(x))) return 'Linux';
        if (/macos|os x|xcode/.test(p) || pub.includes('apple')) return 'macOS';
        if (/iphone|ipad|ipados|on ios|for ios/.test(p)) return 'iOS';
        if (/android/.test(p)) return 'Android';
        return 'non-Windows';
      })();
      return res.json({
        ok: true, tenantId, classification, finding: enrichedFinding,
        plan: {
          executor: 'none',
          supported: false,
          remediationType: 'manual-review',
          autoRemediate: false,
          app: null, candidates: [], checkedSources: [],
          executionMode: 'guided-manual',
          message: `This CVE affects a ${platformHint} platform. Automated remediation via Intune WinGet is only available for Windows applications. Remediate through the platform's native package manager or app store.`,
          statusCard: {
            code: 'unsupported-platform',
            label: `${platformHint} · not supported`,
            tone: 'warning',
            message: `${platformHint} platform — Intune WinGet remediation does not apply. Use the platform's native update mechanism.`
          },
          executionPath: {
            classification: 'unsupported-platform',
            family: 'non-windows',
            executor: 'none',
            status: 'manual',
            route: `${platformHint} → Manual / native package manager`
          },
          manualSteps: platformHint === 'Linux'
            ? [
                'Identify all affected Linux devices using the Exposed devices tab.',
                'Run the appropriate package manager: `apt-get upgrade <package>` (Debian/Ubuntu) or `yum update <package>` (RHEL/CentOS).',
                'Verify remediation by re-running a Defender scan or checking the package version.',
                'Document the action taken and mark the case as resolved.'
              ]
            : platformHint === 'macOS'
            ? [
                'Identify all affected macOS devices.',
                'Deploy the update via Jamf, Mosyle, or the relevant MDM solution for macOS.',
                'Alternatively, use `brew upgrade <package>` if Homebrew is centrally managed.',
                'Verify remediation and document.'
              ]
            : (platformHint === 'iOS' || platformHint === 'Android')
            ? [
                'Identify all affected mobile devices.',
                'Ensure the app is set to auto-update via the App Store / Google Play, or push the update via Intune MAM or Apple Business Manager.',
                'Verify device compliance status in Intune.',
                'Document the action taken.'
              ]
            : [
                'Identify all affected devices using the Exposed devices tab.',
                'Apply the vendor-recommended update or patch on each affected device.',
                'Verify remediation by re-running a Defender scan.',
                'Document the action taken and mark the case as resolved.'
              ],
        }
      });
    }

    if (classification.type === 'application') {
      // Fast catalog resolve — no Graph calls at plan time, only at execute time
      const resolved = await resolveApplicationRemediation(enrichedFinding);
      const isResolved = resolved.ok && resolved.supported;
      const plan = {
        executor: 'local-winget',
        supported: isResolved,
        remediationType: isResolved ? 'winget-intune-upgrade' : 'manual-review',
        autoRemediate: isResolved,
        app: resolved.app || null,
        candidates: [],
        checkedSources: ['local-catalog'],
        message: resolved.message || (isResolved
          ? `Ready to deploy "${resolved.app?.displayName}" (${resolved.app?.wingetId}) via Intune WinGet.`
          : 'No WinGet package found. Manual remediation required.'),
        executionMode: isResolved ? 'local-winget-live' : 'guided-manual',
        statusCard: {
          code: isResolved ? 'local-winget-ready' : 'no-winget-package',
          label: isResolved ? 'WinGet · ready' : 'manual remediation',
          tone: isResolved ? 'success' : 'warning',
          message: isResolved
            ? `Package resolved: ${resolved.app?.wingetId}. Click Execute to deploy via Intune.`
            : resolved.message || 'No matching WinGet package found for this CVE.',
        },
        executionPath: {
          classification: 'application',
          family: 'software',
          executor: isResolved ? 'local-winget' : 'guided-manual',
          status: isResolved ? 'ready' : 'manual',
          route: isResolved
            ? `Application → WinGet (${resolved.app?.wingetId}) → Intune All Devices`
            : 'Application → Manual remediation',
        },
        ...(!isResolved && {
          manualSteps: [
            'Identify all affected devices using the Exposed devices tab.',
            'Apply the vendor-recommended update or patch on each affected device.',
            'Verify remediation by re-running a Defender scan.',
            'Document the action taken and mark the case as resolved.'
          ],
        }),
      };
      return res.json({ ok: true, tenantId, classification, finding: enrichedFinding, plan });
    }

    const plan = await planNativeRemediation({ classification, finding: enrichedFinding, options });
    return res.json({ ok: true, tenantId, classification, finding: enrichedFinding, plan });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message, details: error.details || null });
  }
});

router.post('/execute', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const { approvalId = null, finding = {}, devices = [], plan = {}, options = {} } = req.body || {};
    const enrichedFinding = enrichFinding(finding);
    const classification = enrichedFinding.classification || classifyFinding(enrichedFinding);

    const cveId       = enrichedFinding.cveId || enrichedFinding.id || finding.cveId || finding.id || '';
    const productName = enrichedFinding.productName || enrichedFinding.displayProductName || '';
    const category    = classification.type || 'unknown';
    const severity    = enrichedFinding.severity || finding.severity || '';

    /** Helper: persist result to history and send email notification (fire-and-forget) */
    function saveHistory(status, message, result) {
      saveRemediationRecord({
        tenantId, cveId, productName, category, severity,
        status, message,
        executor:    'manual',
        triggeredBy: 'ui',
        result,
      }).then(record => {
        if (record && (status === 'success' || status === 'failed')) {
          sendRemediationNotification(record, tenantId).catch(() => {});
        }
      }).catch(() => {});
    }

    if (plan.executor === 'local-winget' || plan.executor === 'webapp' || classification.type === 'application') {
      try {
        const result = await executeApplicationRemediation({ tenantId, approvalId, finding: enrichedFinding, devices, plan, options });
        const ok = result?.ok !== false && result?.status !== 'failed';
        saveHistory(ok ? 'success' : 'failed', result?.message || '', result);
        return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'local-winget', result });
      } catch (execError) {
        console.error('[Remediation/execute] local-winget failed:', execError?.message, execError?.status);
        const isNotSupported = execError?.status === 400 || execError?.status === 403;
        const failResult = {
          supported: false,
          status: isNotSupported ? 'unsupported-application' : 'execution-error',
          executionMode: 'guided-manual',
          message: execError?.message || 'Remediation execution failed.',
          details: execError?.details || null,
        };
        saveHistory('failed', failResult.message, failResult);
        return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'local-winget', result: failResult });
      }
    }

    // Immediate Windows Update (Update Now button)
    if ((classification.type === 'windows-update' || options.updateMode === 'immediate') && options.updateMode === 'immediate') {
      const updateType = options.updateType === 'feature' ? 'feature' : 'security';
      const deviceIds = options.deviceIds || devices || [];
      const affectedDeviceNames = options.affectedDeviceNames || enrichedFinding.affectedMachines || [];

      const result = await executeImmediateWindowsUpdate(tenantId, updateType, deviceIds, affectedDeviceNames);
      const ok = result?.ok !== false;
      saveHistory(ok ? 'success' : 'failed', result?.message || 'Windows Update dispatched.', result);
      return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result });
    }

    const result = await executeNativeRemediation({
      tenantId,
      finding: enrichedFinding,
      classification,
      options: {
        ...options,
        deviceIds: options.deviceIds || devices,
        affectedDeviceNames: options.affectedDeviceNames || enrichedFinding.affectedMachines || []
      }
    });
    const ok = result?.ok !== false;
    saveHistory(ok ? 'success' : 'failed', result?.message || '', result);
    return res.json({ ok: true, tenantId, approvalId, forwardedTo: 'native', result });
  } catch (error) {
    return res.status(error.status || 500).json({
      ok: false,
      error: error.message,
      details: error.details || null,
      ...(error.needsConsent ? { needsConsent: true } : {})
    });
  }
});

// ── Remediation History ───────────────────────────────────────────────────────

router.get('/history', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const limit = Math.min(Number(req.query?.limit || 200), 500);
    // Fetch once; derive stats from the same records — avoids a second Azure round-trip.
    const records = await getRemediationHistory(tenantId, { limit: Math.max(limit, 500) });
    const stats   = await getRemediationStats(tenantId, records);
    const trimmed = limit > 0 ? records.slice(0, limit) : records;
    return res.json({ ok: true, tenantId, records: trimmed, total: records.length, stats });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message });
  }
});

// Keep /history/stats for backwards compat but serve from same single fetch
router.get('/history/stats', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest({ session: req.session, body: { tenantId: req.query?.tenantId || null } });
    const records = await getRemediationHistory(tenantId, { limit: 500 });
    const stats   = await getRemediationStats(tenantId, records);
    return res.json({ ok: true, tenantId, stats });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message });
  }
});

// ── Auto-Remediation Control ──────────────────────────────────────────────────

router.get('/auto-remediation/status', async (req, res) => {
  return res.json({
    ok: true,
    enabled: autoRemediationService.isEnabled(),
    intervalMinutes: Math.max(5, Number(process.env.AUTO_REMEDIATION_INTERVAL_MINUTES || 60)),
    maxPerRun: Math.max(1, Math.min(Number(process.env.AUTO_REMEDIATION_MAX_PER_RUN || 10), 50)),
  });
});

// Fire-and-forget: return a jobId immediately, run in background.
// Azure App Service has a 230s gateway timeout so we cannot await the full run.
router.post('/auto-remediation/trigger', async (req, res) => {
  try {
    const tenantId = getTenantIdFromRequest(req);
    const jobId = `${Date.now()}-${Math.random().toString(36).substr(2, 8)}`;
    _autoRemJobs.set(jobId, { status: 'running' });

    // 8-minute hard ceiling. The HTTP response is already sent (fire-and-forget),
    // so this only controls when the background job is marked failed vs completed.
    const RUN_TIMEOUT_MS = 8 * 60 * 1000;
    const runPromise = autoRemediationService.runForTenant(tenantId);
    const timeoutPromise = new Promise((_, reject) =>
      setTimeout(() => reject(new Error('Auto-remediation run timed out after 8 minutes')), RUN_TIMEOUT_MS)
    );
    Promise.race([runPromise, timeoutPromise])
      .then(summaries => {
        _autoRemJobs.set(jobId, { status: 'completed', summaries: summaries || [] });
        _cleanupJob(jobId);
      })
      .catch(err => {
        _autoRemJobs.set(jobId, { status: 'error', error: err.message || 'Run failed.' });
        _cleanupJob(jobId);
      });

    res.json({ ok: true, jobId, status: 'running' });
  } catch (error) {
    return res.status(error.status || 500).json({ ok: false, error: error.message });
  }
});

// Poll endpoint — frontend calls this every 2s until status !== 'running'
router.get('/auto-remediation/job/:jobId', async (req, res) => {
  const job = _autoRemJobs.get(req.params.jobId);
  if (!job) {
    // Job not found — server restarted and cleared in-memory map, or jobId expired
    return res.json({ status: 'error', error: 'Job not found — the server restarted during the run. Please try again.' });
  }
  res.json(job);
});

module.exports = router;
