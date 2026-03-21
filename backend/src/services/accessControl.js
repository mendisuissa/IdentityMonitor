const settingsService = require('./settingsService');

const ROLE_MATRIX = {
  owner: ['alerts.view','alerts.respond','alerts.approve','users.respond','settings.manage','audit.view','audit.export','ops.view'],
  admin: ['alerts.view','alerts.respond','alerts.approve','users.respond','settings.manage','audit.view','ops.view'],
  responder: ['alerts.view','alerts.respond','users.respond','audit.view','ops.view'],
  analyst: ['alerts.view','audit.view','ops.view'],
  viewer: ['alerts.view','audit.view'],
  msp_operator: ['alerts.view','alerts.respond','alerts.approve','users.respond','audit.view','audit.export','ops.view']
};

function getTenantId(req) {
  return req.session?.tenant?.tenantId || null;
}

function getActor(req) {
  return req.session?.tenant?.userEmail || 'mock@example.com';
}

function getRoleForRequest(req) {
  if (process.env.MOCK_MODE === 'true') return 'owner';
  const tenantId = getTenantId(req);
  if (!tenantId) return 'viewer';
  const email = (getActor(req) || '').toLowerCase();
  const admins = settingsService.getAdmins(tenantId) || [];
  const matched = admins.find(a => String(a.email || '').toLowerCase() === email);
  return matched?.role || 'owner';
}

function getAccessForRequest(req) {
  const role = getRoleForRequest(req);
  return { role, permissions: ROLE_MATRIX[role] || ROLE_MATRIX.viewer };
}

function can(req, permission) {
  const { permissions } = getAccessForRequest(req);
  return permissions.includes(permission);
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (process.env.MOCK_MODE === 'true') return next();
    if (!getTenantId(req)) return res.status(401).json({ error: 'Not authenticated' });
    if (!can(req, permission)) return res.status(403).json({ error: 'Insufficient permissions' });
    next();
  };
}

module.exports = { ROLE_MATRIX, getAccessForRequest, requirePermission, can, getRoleForRequest, getActor, getTenantId };
