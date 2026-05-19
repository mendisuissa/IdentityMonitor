// auditAnomalyEngine.js — Behavioral anomaly detection on directory audit actions
//
// Watches 3 threat patterns for privileged users:
//   1. UNUSUAL_DELETION     — more deletions than historical baseline
//   2. UNUSUAL_RULE_CREATION — policy/rule/CA creation outside normal pattern
//   3. LATERAL_MOVEMENT      — role/group/permission changes (always suspicious)
//
// Each pattern compares today's count against a 30-day rolling daily average.

// ─── Classification rules ─────────────────────────────────────────────────

const DELETION_PREFIXES = ['delete ', 'remove ', 'purge ', 'hard delete'];

// Activities that represent policy/rule creation risk
const RULE_KEYWORDS = [
  'conditional access policy',
  'transport rule', 'mail flow rule',
  'dlp policy', 'data loss prevention',
  'named location',
  'authentication method', 'authentication policy', 'authentication strength',
  'security default',
  'role assignment schedule',
  'cross-tenant access',
  'application access policy',
  'permission grant policy',
  'administrative unit',
];

// Activities that represent lateral movement / privilege escalation
const LATERAL_ACTIVITIES = [
  'add member to role',
  'add eligible member to role',
  'add permanent eligible member',
  'add member to group',
  'add owner to group',
  'add owner to application',
  'add owner to service principal',
  'add app role assignment to user',
  'add app role assignment to service principal',
  'add app role assignment grant to user',
  'add delegated permission grant',
  'add oauth2permissiongrant',
  'consent to application',
  'add service principal credentials',
  'update service principal',
  'add service principal',
  'set company information',  // tenant-wide config changes
];

function classifyAction(action) {
  const name = (action.activityDisplayName || '').toLowerCase().trim();
  const op   = (action.operationType     || '').toLowerCase().trim();

  if (DELETION_PREFIXES.some(p => name.startsWith(p)) || op === 'delete') {
    return 'deletion';
  }
  if (LATERAL_ACTIVITIES.some(a => name.includes(a))) {
    return 'lateral_movement';
  }
  // Rule/policy creation: must be a create/add/set operation on a known policy type
  const isCreateOp = op === 'add' || name.startsWith('add ') || name.startsWith('create ') || name.startsWith('set ') || name.startsWith('update ');
  if (isCreateOp && RULE_KEYWORDS.some(k => name.includes(k))) {
    return 'rule_creation';
  }
  return null;
}

// ─── Statistics helpers ───────────────────────────────────────────────────

function mean(arr) {
  if (!arr.length) return 0;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  if (arr.length < 2) return 0;
  const m = mean(arr);
  return Math.sqrt(arr.reduce((sum, x) => sum + (x - m) ** 2, 0) / arr.length);
}

// Flags current count as unusual vs historical daily counts
// Threshold = max(mean + 2σ, mean×3, 2) — avoids false positives on low-volume users
function isUnusual(current, history) {
  if (current === 0) return false;
  if (!history.length) return true; // no baseline = any activity is novel
  const m = mean(history);
  const s = stddev(history);
  const threshold = Math.max(m + 2 * s, m * 3, 2);
  return current >= threshold;
}

// ─── Score a batch of audit actions against the user's baseline ───────────

function scoreAuditActions(actions, auditBaseline) {
  const baseline = auditBaseline || { dailyActionCounts: { deletions: [], ruleCreations: [], lateralMoves: [] } };
  const dac = baseline.dailyActionCounts || { deletions: [], ruleCreations: [], lateralMoves: [] };

  const deletions    = actions.filter(a => classifyAction(a) === 'deletion');
  const ruleCreations = actions.filter(a => classifyAction(a) === 'rule_creation');
  const lateralMoves  = actions.filter(a => classifyAction(a) === 'lateral_movement');

  const factors   = [];
  let baseScore   = 0;

  // ── Factor 1: Unusual deletions ─────────────────────────────────────────
  const hist_del = dac.deletions.map(d => d.count);
  if (isUnusual(deletions.length, hist_del)) {
    const score = Math.min(60, 20 + deletions.length * 5);
    baseScore  += score;
    const targets = [...new Set(
      deletions.flatMap(a => (a.targetResources || []).map(t => t.displayName || t.userPrincipalName).filter(Boolean))
    )].slice(0, 4).join(', ');
    factors.push({
      type:    'UNUSUAL_DELETION',
      score,
      detail:  `${deletions.length} deletion(s) — avg ${mean(hist_del).toFixed(1)}/day${targets ? '. Targets: ' + targets : ''}`,
      actions: deletions.map(a => a.activityDisplayName),
    });
  }

  // ── Factor 2: Suspicious rule/policy creation ────────────────────────────
  const hist_rule = dac.ruleCreations.map(d => d.count);
  if (isUnusual(ruleCreations.length, hist_rule)) {
    const score = Math.min(70, 30 + ruleCreations.length * 8);
    baseScore  += score;
    const names = [...new Set(ruleCreations.map(a => a.activityDisplayName))].slice(0, 3).join(', ');
    factors.push({
      type:    'UNUSUAL_RULE_CREATION',
      score,
      detail:  `${ruleCreations.length} policy/rule creation(s) outside normal pattern: ${names}`,
      actions: ruleCreations.map(a => a.activityDisplayName),
    });
  }

  // ── Factor 3: Lateral movement — always suspicious for privileged users ──
  if (lateralMoves.length > 0) {
    const score = Math.min(85, 40 + lateralMoves.length * 10);
    baseScore  += score;
    const detail = lateralMoves.map(a => {
      const t = (a.targetResources || [])[0];
      const tName = t?.displayName || t?.userPrincipalName || t?.id || '?';
      return `${a.activityDisplayName} → ${tName}`;
    }).slice(0, 3).join(' | ');
    factors.push({
      type:    'LATERAL_MOVEMENT',
      score,
      detail:  `${lateralMoves.length} role/group/permission change(s): ${detail}`,
      actions: lateralMoves.map(a => ({
        activity: a.activityDisplayName,
        target:   (a.targetResources || [])[0]?.displayName || (a.targetResources || [])[0]?.userPrincipalName || null,
        time:     a.activityDateTime,
      })),
    });
  }

  if (factors.length === 0) return { isClean: true, score: 0, factors: [] };

  const finalScore = Math.min(100, baseScore);
  let severity;
  if      (finalScore >= 75) severity = 'critical';
  else if (finalScore >= 50) severity = 'high';
  else if (finalScore >= 25) severity = 'medium';
  else                       severity = 'low';

  return { isClean: false, score: finalScore, severity, factors };
}

// ─── Update audit action baseline (called after each scan) ────────────────

function updateAuditBaseline(auditBaseline, actions, date) {
  date = date || new Date().toISOString().slice(0, 10);
  if (!auditBaseline) auditBaseline = {};
  if (!auditBaseline.dailyActionCounts) {
    auditBaseline.dailyActionCounts = { deletions: [], ruleCreations: [], lateralMoves: [] };
  }
  const dac = auditBaseline.dailyActionCounts;

  const push = (arr, count) => {
    const existing = arr.find(e => e.date === date);
    if (existing) { existing.count = count; } else { arr.push({ date, count }); }
    arr.sort((a, b) => a.date.localeCompare(b.date));
    while (arr.length > 30) arr.shift(); // keep 30-day rolling window
  };

  push(dac.deletions,    actions.filter(a => classifyAction(a) === 'deletion').length);
  push(dac.ruleCreations, actions.filter(a => classifyAction(a) === 'rule_creation').length);
  push(dac.lateralMoves,  actions.filter(a => classifyAction(a) === 'lateral_movement').length);

  auditBaseline.lastUpdated = new Date().toISOString();
  return auditBaseline;
}

// ─── Anomaly label map (exported for alert display) ──────────────────────

const ANOMALY_LABELS = {
  UNUSUAL_DELETION:      'Unusual Deletion Activity',
  UNUSUAL_RULE_CREATION: 'Suspicious Policy/Rule Creation',
  LATERAL_MOVEMENT:      'Lateral Movement Detected',
};

module.exports = { scoreAuditActions, updateAuditBaseline, classifyAction, ANOMALY_LABELS };
