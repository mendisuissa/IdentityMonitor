// identity.js — Express router for Identity/Conditional Access endpoints
// Mounted at /api/identity

const express = require('express');
const router  = express.Router();

const caService        = require('../services/conditionalAccessService');
const { requirePermission } = require('../services/accessControl');

// ─── Helper: extract tenantId from session ────────────────────────────────
function getTenantId(req) {
  return req.session && req.session.tenant ? req.session.tenant.tenantId : null;
}

// ─── Helper: send error response, detecting 403 permission errors ─────────
function sendError(res, err, defaultStatus) {
  const status = err.statusCode || defaultStatus || 500;
  const body   = { error: err.message || String(err) };
  if (err.isPermissionError || status === 403) {
    body.needsConsent = true;
  }
  return res.status(status).json(body);
}

// ─────────────────────────────────────────────────────────────────────────
// CA POLICIES
// ─────────────────────────────────────────────────────────────────────────

// GET /api/identity/ca-policies
router.get('/ca-policies', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const policies = await caService.listCaPolicies(tenantId);
    res.json(policies);
  } catch (err) {
    sendError(res, err);
  }
});

// GET /api/identity/ca-policies/:id
router.get('/ca-policies/:id', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const policy = await caService.getCaPolicy(tenantId, req.params.id);
    res.json(policy);
  } catch (err) {
    sendError(res, err);
  }
});

// PATCH /api/identity/ca-policies/:id — toggle state
router.patch('/ca-policies/:id', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { state } = req.body || {};
  if (!state) return res.status(400).json({ error: 'state is required' });
  try {
    const result = await caService.toggleCaPolicy(tenantId, req.params.id, state);
    res.json(result || { ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// DELETE /api/identity/ca-policies/:id
router.delete('/ca-policies/:id', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    await caService.deleteCaPolicy(tenantId, req.params.id);
    res.json({ ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// NAMED LOCATIONS
// ─────────────────────────────────────────────────────────────────────────

// GET /api/identity/named-locations
router.get('/named-locations', async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  try {
    const locations = await caService.listNamedLocations(tenantId);
    res.json(locations);
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// IP BLOCKING
// ─────────────────────────────────────────────────────────────────────────

// POST /api/identity/block-ip
router.post('/block-ip', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { ipAddress, locationName } = req.body || {};
  if (!ipAddress) return res.status(400).json({ error: 'ipAddress is required' });
  try {
    const result = await caService.blockIpAddress(tenantId, ipAddress, locationName);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// DELETE /api/identity/block-ip
router.delete('/block-ip', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { ipAddress, locationName } = req.body || {};
  if (!ipAddress) return res.status(400).json({ error: 'ipAddress is required' });
  try {
    const result = await caService.removeIpBlock(tenantId, ipAddress, locationName);
    res.json(result || { ok: true });
  } catch (err) {
    sendError(res, err);
  }
});

// ─────────────────────────────────────────────────────────────────────────
// MFA / BLOCK USER POLICIES
// ─────────────────────────────────────────────────────────────────────────

// POST /api/identity/require-mfa
router.post('/require-mfa', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { userId, policyName } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  try {
    const result = await caService.requireMfaForUser(tenantId, userId, policyName);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

// POST /api/identity/block-user
router.post('/block-user', requirePermission('settings.manage'), async (req, res) => {
  const tenantId = getTenantId(req);
  if (!tenantId) return res.status(401).json({ error: 'Not authenticated' });
  const { userId, policyName } = req.body || {};
  if (!userId) return res.status(400).json({ error: 'userId is required' });
  try {
    const result = await caService.blockUserSignIn(tenantId, userId, policyName);
    res.json(result);
  } catch (err) {
    sendError(res, err);
  }
});

module.exports = router;
