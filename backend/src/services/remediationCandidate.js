'use strict';
const crypto = require('node:crypto');

// No provider imports/credentials. Production legacy executors remain held.
function canonical(value) {
  if (value === null || ['string','boolean'].includes(typeof value)) return JSON.stringify(value);
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && Object.getPrototypeOf(value) === Object.prototype) return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  throw new Error('P0_INVALID_REMEDIATION_PLAN');
}
const identifier = value => typeof value === 'string' && /^[a-zA-Z0-9_.:-]{1,128}$/.test(value) && !['all','all-devices','latest'].includes(value.toLowerCase());
function validateRemediation(artifact, destinations) {
  if (!artifact || artifact.action !== 'identity.remediate' || !destinations.has(artifact.destination) || Object.keys(artifact).some(k => !['action','destination','content','evidence','media','notBefore','expiresAt'].includes(k))) throw new Error('P0_INVALID_REMEDIATION');
  const plan = artifact.content;
  const fields = ['tenantId','deviceIds','userIds','packageId','targetVersion','operation','parameters','executionTarget',...(plan?.delegation ? ['delegation'] : [])];
  if (!plan || Object.keys(plan).length !== fields.length || !fields.every(k => Object.hasOwn(plan,k))) throw new Error('P0_INVALID_REMEDIATION_PLAN');
  if (plan.delegation && (Object.keys(plan.delegation).length !== 2 || !identifier(plan.delegation.callerId) || !identifier(plan.delegation.requestId))) throw new Error('P0_INVALID_DELEGATION');
  if (![plan.tenantId,plan.packageId,plan.targetVersion,plan.executionTarget].every(identifier) || plan.executionTarget !== artifact.destination) throw new Error('P0_INVALID_REMEDIATION_SCOPE');
  if (!Array.isArray(plan.deviceIds) || !plan.deviceIds.length || !plan.deviceIds.every(identifier) || new Set(plan.deviceIds).size !== plan.deviceIds.length || !Array.isArray(plan.userIds) || plan.userIds.length) throw new Error('P0_INVALID_REMEDIATION_TARGETS');
  // Only exact-version package upgrade is integrated. Every other operation
  // (including user/session/CA/script actions) stays behind unconditional holds.
  if (plan.operation !== 'upgrade_package') throw new Error('P0_UNSUPPORTED_REMEDIATION_OPERATION');
  if (!plan.parameters || Object.keys(plan.parameters).length !== 2 || plan.parameters.installMode !== 'upgrade-only' || !['suppress','ifRequired'].includes(plan.parameters.rebootBehavior)) throw new Error('P0_INVALID_REMEDIATION_PARAMETERS');
  if (!Array.isArray(artifact.media) || artifact.media.length || !Array.isArray(artifact.evidence) || !artifact.evidence.length || !artifact.evidence.every(e => typeof e === 'string' && e.trim()) || !Number.isSafeInteger(artifact.notBefore) || !Number.isSafeInteger(artifact.expiresAt) || artifact.expiresAt <= artifact.notBefore) throw new Error('P0_INVALID_REMEDIATION_EVIDENCE');
  return Object.freeze({status:'PASS',version:'identity-p0-2',hash:crypto.createHash('sha256').update(canonical(artifact)).digest('hex')});
}
function createRemediationCandidateSubmitter(client) {
  return ({tenantId,deviceId,deviceIds = deviceId ? [deviceId] : [],userIds = [],packageId,targetVersion,executionTarget,operation = 'upgrade_package',parameters = {installMode:'upgrade-only',rebootBehavior:'suppress'},evidence,notBefore,expiresAt,delegation,...unknown}) => {
    if (Object.keys(unknown).length || (deviceId && (deviceIds.length !== 1 || deviceIds[0] !== deviceId))) throw new Error('P0_UNKNOWN_REMEDIATION_FIELD');
    return client.submitCandidate({action:'identity.remediate',content:{tenantId,deviceIds,userIds,packageId,targetVersion,executionTarget,operation,parameters,...(delegation === undefined ? {} : {delegation})},evidence,media:[],...(notBefore === undefined ? {} : {notBefore}),...(expiresAt === undefined ? {} : {expiresAt})});
  };
}

// Trusted local composition injects the EXISTING P0 core, never a request body.
// Requesters receive client only. No production target or signer is installed.
function createRemediationWorkflow({createExecutor,createSafetyClient,store,auth,target,tenantId,executionTarget,generator,now=Date.now,operationTimeoutMs=30000}) {
  if (![createExecutor,createSafetyClient,target?.check,target?.execute,target?.read,target?.lookup].every(fn=>typeof fn==='function') || !identifier(tenantId) || !identifier(executionTarget)) throw new Error('P0_REMEDIATION_CONFIGURATION_REQUIRED');
  const adapter = {
    async preflight(artifact) { return await target.check(artifact.content) === true; },
    async execute(artifact,context) {
      const receipt=await target.execute(artifact.content,context);
      if (!receipt || receipt.status !== 'EXECUTION_ACCEPTED' || typeof receipt.externalId !== 'string' || !receipt.externalId) throw new Error('P0_REMEDIATION_NOT_ACCEPTED');
      store.event(context.idempotencyKey,'EXECUTION_ACCEPTED',now());
      return {externalId:receipt.externalId};
    },
    async verify(artifact,receipt,context) {
      const plan=artifact.content;
      const observed=await target.read({tenantId:plan.tenantId,executionTarget:plan.executionTarget,deviceIds:plan.deviceIds,packageId:plan.packageId,externalId:receipt.externalId});
      if (!observed || observed.tenantId !== plan.tenantId || observed.executionTarget !== plan.executionTarget) return false;
      if (observed.status === 'FAILED') { store.event(context.idempotencyKey,'INDEPENDENT_FAILURE_OBSERVED',now()); return false; }
      return observed.status === 'COMPLETED' && Array.isArray(observed.devices) && observed.devices.length === plan.deviceIds.length && plan.deviceIds.every(id=>observed.devices.filter(d=>d.deviceId===id && d.packageId===plan.packageId && d.version===plan.targetVersion).length===1);
    },
    async lookup(artifact,context) { return target.lookup({tenantId,executionTarget,plan:artifact.content,idempotencyKey:context.idempotencyKey}); }
  };
  const executor=createExecutor({store,auth,adapters:{'identity.remediate':adapter},destinations:[executionTarget],now,operationTimeoutMs,
    validateArtifact(artifact,allowed) { const result=validateRemediation(artifact,allowed); if (artifact.content.tenantId!==tenantId) throw new Error('P0_TENANT_SCOPE_MISMATCH'); return result; }});
  const client=createSafetyClient({submit:executor.submit,generator,destination:executionTarget,now});
  const operator=Object.freeze({...executor,status(id) {
    const row=store.get(id);if(!row) throw new Error('P0_NOT_FOUND');
    const events=store.db.prepare('SELECT event FROM p0_events WHERE id=? ORDER BY seq').all(id).map(r=>r.event);
    const states={APPROVED:executor.isAuthorized(id)?'AUTHORIZED':'FAILED',EXECUTING:events.includes('EXECUTION_ACCEPTED')?'EXECUTION_ACCEPTED':'EXECUTION_STARTED',VERIFIED:'VERIFIED',OUTCOME_UNKNOWN:events.includes('INDEPENDENT_FAILURE_OBSERVED')?'FAILED':'OUTCOME_UNKNOWN',REVOKED:'FAILED'};
    return Object.freeze({status:states[row.state] || row.state,executionAccepted:events.includes('EXECUTION_ACCEPTED'),retryAllowed:false});
  }});
  return Object.freeze({client,operator});
}
module.exports = {validateRemediation,createRemediationCandidateSubmitter,createRemediationWorkflow};
