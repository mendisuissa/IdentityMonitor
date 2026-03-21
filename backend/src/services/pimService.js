// pimService.js — PIM (Privileged Identity Management) Analysis
// Detects: permanent admins, missing JIT, over-privileged accounts
// Recommends: converting to Eligible, enabling PIM, reducing admin count

const graphService = require('./graphService');

// ─── Analyze PIM status for a tenant ─────────────────────────────────────
async function analyzePimStatus(tenantId) {
  const client = await graphService.getClientForTenant(tenantId);
  const findings = [];
  const recommendations = [];
  const bestPracticeRecommendations = [];

  try {
    // 1. Get all privileged role assignments (permanent = Active, JIT = Eligible)
    const [permanentAssignments, eligibleAssignments, roleDefinitions] = await Promise.all([
      getPermanentAssignments(client),
      getEligibleAssignments(client),
      getRoleDefinitions(client)
    ]);

    const roleMap = new Map(roleDefinitions.map(r => [r.id, r.displayName]));

    // 2. Critical roles that should NEVER be permanent
    const CRITICAL_ROLES = [
      'Global Administrator',
      'Privileged Role Administrator',
      'Security Administrator',
      'Exchange Administrator',
      'SharePoint Administrator'
    ];

    // 3. Find permanent assignments of critical roles
    const permanentCritical = permanentAssignments.filter(a => {
      const roleName = roleMap.get(a.roleDefinitionId) || '';
      return CRITICAL_ROLES.some(cr => roleName.includes(cr));
    });

    if (permanentCritical.length > 0) {
      findings.push({
        type:     'PERMANENT_CRITICAL_ROLE',
        severity: 'critical',
        count:    permanentCritical.length,
        title:    `${permanentCritical.length} permanent Critical Role assignment${permanentCritical.length > 1 ? 's' : ''}`,
        detail:   'Critical roles should use Just-in-Time (Eligible) access, not permanent assignment.',
        users:    permanentCritical.map(a => ({
          userId:   a.principalId,
          roleName: roleMap.get(a.roleDefinitionId) || a.roleDefinitionId,
          assignedAt: a.startDateTime
        })).slice(0, 10),
        recommendation: 'Convert to Eligible assignment in PIM. Require approval + MFA for activation.'
      });
      recommendations.push({
        priority: 'critical',
        action:   'Convert permanent Global Admins to PIM Eligible',
        impact:   'Eliminates standing access — attack window reduced from 24/7 to activation duration only',
        effort:   'low',
        howTo:    'Entra Admin → Identity Governance → Privileged Identity Management → Azure AD roles → Assignments → Convert to eligible'
      });
    }

    // 4. Check Global Admin count (>2 permanent = risky, >5 = very risky)
    const globalAdmins = permanentAssignments.filter(a =>
      roleMap.get(a.roleDefinitionId) === 'Global Administrator'
    );

    if (globalAdmins.length > 5) {
      findings.push({
        type:     'EXCESSIVE_GLOBAL_ADMINS',
        severity: 'high',
        count:    globalAdmins.length,
        title:    `${globalAdmins.length} permanent Global Administrators`,
        detail:   'Best practice: ≤2 permanent Global Admins. Use PIM Eligible for the rest.',
        recommendation: `Reduce to 2 permanent Global Admins. Convert ${globalAdmins.length - 2} to Eligible.`
      });
      recommendations.push({
        priority: 'high',
        action:   `Reduce permanent Global Admin count from ${globalAdmins.length} to 2`,
        impact:   'Smaller blast radius if credentials compromised',
        effort:   'medium',
        howTo:    'Review each Global Admin — keep only break-glass accounts as permanent'
      });
    } else if (globalAdmins.length > 2) {
      findings.push({
        type:     'TOO_MANY_GLOBAL_ADMINS',
        severity: 'medium',
        count:    globalAdmins.length,
        title:    `${globalAdmins.length} permanent Global Administrators (best practice: ≤2)`,
        detail:   'Microsoft recommends fewer than 5 permanent Global Admins.',
        recommendation: 'Consider converting some to Eligible with PIM.'
      });
    }

    // 5. Check if PIM is not being used at all
    const pimNotUsed = eligibleAssignments.length === 0 && permanentAssignments.length > 3;
    if (pimNotUsed) {
      findings.push({
        type:     'PIM_NOT_CONFIGURED',
        severity: 'critical',
        count:    permanentAssignments.length,
        title:    'PIM (Just-in-Time) is not configured',
        detail:   `All ${permanentAssignments.length} privileged role assignments are permanent. No JIT access found.`,
        recommendation: 'Enable Privileged Identity Management. Requires Entra ID P2 license.'
      });
      recommendations.push({
        priority: 'critical',
        action:   'Enable Privileged Identity Management (PIM)',
        impact:   'JIT access eliminates 80%+ of insider threat and credential theft risk',
        effort:   'medium',
        howTo:    'Entra Admin → Identity Governance → Privileged Identity Management → Discover',
        requiresLicense: 'Entra ID P2'
      });
    }

    // 6. Check for stale assignments (assigned > 90 days, never activated)
    const ninetyDaysAgo = new Date(Date.now() - 90 * 24 * 3600 * 1000);
    const staleAssignments = permanentAssignments.filter(a =>
      a.startDateTime && new Date(a.startDateTime) < ninetyDaysAgo
    );

    if (staleAssignments.length > 0) {
      findings.push({
        type:     'STALE_ASSIGNMENTS',
        severity: 'medium',
        count:    staleAssignments.length,
        title:    `${staleAssignments.length} role assignments older than 90 days`,
        detail:   'Old assignments may belong to former employees or unused service accounts.',
        recommendation: 'Review and remove assignments that are no longer needed.'
      });
    }


    // 6.5 Baseline best-practice guidance (always useful, even when green)
    bestPracticeRecommendations.push(
      {
        priority: 'low',
        type: 'best-practice',
        action: 'Review eligible role assignments every 30 days',
        impact: 'Keeps privileged access aligned with current job scope and ownership',
        effort: 'low',
        howTo: 'Run a monthly access review for privileged role eligibility and remove stale entitlements'
      },
      {
        priority: scoreToPriority(globalAdmins.length > 0 || permanentCritical.length > 0 ? 'medium' : 'low'),
        type: 'best-practice',
        action: 'Require approval + MFA for critical role activation',
        impact: 'Adds strong control over Tier-0 activation and reduces unauthorized elevation risk',
        effort: 'medium',
        howTo: 'Entra Admin → Identity Governance → Privileged Identity Management → Azure AD roles → Role settings'
      },
      {
        priority: 'low',
        type: 'best-practice',
        action: 'Validate alerting for privileged access changes',
        impact: 'Improves detection coverage for high-risk role assignments, activation, and policy drift',
        effort: 'low',
        howTo: 'Enable PIM alerts and route them to the SOC / SIEM / notification workflow'
      },
      {
        priority: 'low',
        type: 'best-practice',
        action: 'Perform quarterly privileged access recertification',
        impact: 'Reduces dormant privilege and improves audit readiness',
        effort: 'medium',
        howTo: 'Review all active and eligible privileged assignments with business owners every quarter'
      },
      {
        priority: 'low',
        type: 'best-practice',
        action: 'Test emergency access and break-glass procedures',
        impact: 'Ensures privileged recovery paths work during identity outage or lockout scenarios',
        effort: 'medium',
        howTo: 'Validate exclusion rules, credential custody, monitoring, and sign-in logging for emergency accounts'
      }
    );

    // 7. Calculate overall PIM score (0-100, higher = better)
    let score = calculatePimScore({
      hasPim:           !pimNotUsed,
      permanentCritical: permanentCritical.length,
      globalAdminCount:  globalAdmins.length,
      eligibleCount:     eligibleAssignments.length,
      staleCount:        staleAssignments.length
    });

    const telemetryIncomplete = permanentAssignments.length === 0 && eligibleAssignments.length === 0;
    const warnings = [];
    if (telemetryIncomplete) {
      score = Math.min(score, 35);
      warnings.push('No role assignments or eligible schedules were returned from Graph. Treat this as incomplete telemetry, not a healthy PIM state.');
    }

    return {
      score,
      grade:           scoreToGrade(score),
      findings,
      recommendations: mergeRecommendations(recommendations, bestPracticeRecommendations),
      recommendationSummary: {
        riskBased: recommendations.length,
        bestPractice: bestPracticeRecommendations.length
      },
      stats: {
        permanentCount: permanentAssignments.length,
        eligibleCount:  eligibleAssignments.length,
        globalAdmins:   globalAdmins.length,
        criticalPermanent: permanentCritical.length,
        pimEnabled:     !pimNotUsed,
        telemetryIncomplete
      },
      warnings,
      analyzedAt: new Date().toISOString()
    };

  } catch (err) {
    console.error('[PIM] Analysis error:', err.message);
    // If PIM API not available (no P2 license), do basic analysis
    return basicAnalysis(tenantId);
  }
}

// ─── Get permanent role assignments ──────────────────────────────────────
async function getPermanentAssignments(client) {
  try {
    const result = await client
      .api('/roleManagement/directory/roleAssignments')
      .select('id,principalId,roleDefinitionId,startDateTime,endDateTime,directoryScopeId')
      .top(100)
      .get();
    return (result.value || []).filter(a => !a.endDateTime); // no end = permanent
  } catch (err) {
    console.warn('[PIM] Could not fetch role assignments:', err.message);
    return [];
  }
}

// ─── Get Eligible (JIT) assignments ──────────────────────────────────────
async function getEligibleAssignments(client) {
  try {
    const result = await client
      .api('/roleManagement/directory/roleEligibilitySchedules')
      .select('id,principalId,roleDefinitionId,scheduleInfo')
      .top(100)
      .get();
    return result.value || [];
  } catch (err) {
    // PIM not licensed or not configured
    return [];
  }
}

// ─── Get role definitions ─────────────────────────────────────────────────
async function getRoleDefinitions(client) {
  try {
    const result = await client
      .api('/roleManagement/directory/roleDefinitions')
      .select('id,displayName,isBuiltIn')
      .get();
    return result.value || [];
  } catch (err) {
    return [];
  }
}

// ─── Basic analysis (fallback without PIM API) ────────────────────────────
async function basicAnalysis(tenantId) {
  const users = await graphService.getPrivilegedUsers(tenantId);
  const globalAdmins = users.filter(u => u.roles.includes('Global Administrator'));

  const findings = [];
  if (globalAdmins.length > 2) {
    findings.push({
      type: 'TOO_MANY_GLOBAL_ADMINS', severity: 'medium',
      count: globalAdmins.length,
      title: `${globalAdmins.length} Global Administrators detected`,
      detail: 'Best practice: ≤2 permanent Global Admins with PIM for the rest.',
      users: globalAdmins.map(u => ({ userId: u.id, roleName: 'Global Administrator' }))
    });
  }

  const telemetryIncomplete = users.length === 0;
  const score = telemetryIncomplete ? 25 : (globalAdmins.length <= 2 ? 70 : globalAdmins.length <= 5 ? 50 : 30);

  return {
    score,
    grade: globalAdmins.length <= 2 ? 'B' : 'C',
    findings,
    recommendations: mergeRecommendations(
      findings.length > 0 ? [{
        priority: 'high',
        type: 'risk',
        action: 'Reduce Global Admin count and enable PIM',
        impact: 'Reduce attack surface significantly',
        effort: 'medium',
        howTo: 'Entra Admin → Identity Governance → Privileged Identity Management'
      }] : [],
      [
        {
          priority: 'low',
          type: 'best-practice',
          action: 'Review privileged role ownership monthly',
          impact: 'Keeps privileged access aligned with active administrators only',
          effort: 'low',
          howTo: 'Perform a recurring admin review and document approved owners'
        },
        {
          priority: 'low',
          type: 'best-practice',
          action: 'Test emergency access controls quarterly',
          impact: 'Improves resilience during identity outage or admin lockout',
          effort: 'medium',
          howTo: 'Validate break-glass credentials, exclusions, and monitoring'
        }
      ]
    ),
    recommendationSummary: { riskBased: findings.length > 0 ? 1 : 0, bestPractice: 2 },
    stats: { globalAdmins: globalAdmins.length, pimEnabled: false, telemetryIncomplete },
    warnings: telemetryIncomplete ? ['No privileged users were discovered from Graph. This is incomplete telemetry, not a clean result.'] : [],
    basicAnalysis: true,
    analyzedAt: new Date().toISOString()
  };
}

// ─── Score calculation ────────────────────────────────────────────────────
function calculatePimScore({ hasPim, permanentCritical, globalAdminCount, eligibleCount, staleCount }) {
  let score = 100;
  if (!hasPim)              score -= 40;
  score -= permanentCritical * 15;
  if (globalAdminCount > 5) score -= 20;
  else if (globalAdminCount > 2) score -= 10;
  score -= Math.min(20, staleCount * 5);
  if (eligibleCount > 0)    score += 10; // bonus for using PIM
  return Math.max(0, Math.min(100, score));
}

function scoreToGrade(score) {
  if (score >= 90) return { letter: 'A', label: 'Excellent', color: '#2ecc71' };
  if (score >= 75) return { letter: 'B', label: 'Good',      color: '#4a90d9' };
  if (score >= 60) return { letter: 'C', label: 'Fair',      color: '#f5a623' };
  if (score >= 40) return { letter: 'D', label: 'Poor',      color: '#ff6b35' };
  return             { letter: 'F', label: 'Critical',  color: '#ff3b3b' };
}

module.exports = { analyzePimStatus };


function scoreToPriority(level) {
  return level;
}

function mergeRecommendations(riskRecommendations = [], bestPracticeRecommendations = []) {
  const normalizedRisk = riskRecommendations.map(item => ({ ...item, type: item.type || 'risk' }));
  const normalizedBest = bestPracticeRecommendations.map(item => ({ ...item, type: item.type || 'best-practice' }));
  return [...normalizedRisk, ...normalizedBest];
}
