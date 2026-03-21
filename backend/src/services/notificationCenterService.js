const fs = require('fs');
const path = require('path');

const DIR = process.env.NODE_ENV === 'production' ? '/home/notification-center' : path.join(__dirname, '../../../notification-center');
if (!fs.existsSync(DIR)) fs.mkdirSync(DIR, { recursive: true });

function filePath(tenantId) {
  return path.join(DIR, `${tenantId}.json`);
}

function readStore(tenantId) {
  try {
    if (!fs.existsSync(filePath(tenantId))) return [];
    return JSON.parse(fs.readFileSync(filePath(tenantId), 'utf8')) || [];
  } catch {
    return [];
  }
}

function writeStore(tenantId, items) {
  fs.writeFileSync(filePath(tenantId), JSON.stringify(items, null, 2));
}

function inferEntityLabel(item) {
  const meta = item.metadata || {};
  return meta.userDisplayName || meta.userPrincipalName || meta.user || meta.account || meta.alertLabel || meta.anomalyLabel || '';
}

function inferCaseLabel(item) {
  const meta = item.metadata || {};
  return meta.caseId || meta.alertId || meta.caseLabel || '';
}

function humanizeType(type = '') {
  switch (type) {
    case 'approval': return 'Approval needed';
    case 'mention': return 'Mention';
    case 'sla-breach': return 'SLA breach';
    case 'assignment': return 'Assignment';
    case 'escalation': return 'Escalation';
    default: return type ? String(type).replace(/[-_]/g, ' ') : 'Notification';
  }
}

function formatTitle(item) {
  const typeLabel = humanizeType(item.type);
  const meta = item.metadata || {};
  // Best: use anomalyLabel — most descriptive
  if (meta.anomalyLabel) return `${typeLabel} · ${meta.anomalyLabel}`;
  // Use user display name if available and not a GUID
  const entity = inferEntityLabel(item);
  const isGuidLike = /[0-9a-f]{8}-[0-9a-f]{4}/i.test(entity || '');
  if (entity && !isGuidLike) return `${typeLabel} · ${entity}`;
  // Use title only if short and not a GUID
  const titleIsGuid = /[0-9a-f]{8}-[0-9a-f]{4}/i.test(item.title || '');
  if (item.title && item.title.length < 80 && !titleIsGuid) return item.title;
  return typeLabel;
}

function formatSubtitle(item) {
  const meta = item.metadata || {};
  const parts = [];
  const entity = inferEntityLabel(item);
  if (entity) parts.push(entity);
  if (item.severity) parts.push(String(item.severity).toUpperCase());
  if (meta.currentStepLabel) parts.push(meta.currentStepLabel);
  if (meta.owner) parts.push(`Owner: ${meta.owner}`);
  const caseLabel = inferCaseLabel(item);
  if (caseLabel) parts.push(caseLabel);
  return parts.slice(0, 4).join(' • ');
}

function uniqueKeyFor(item) {
  if (item.uniqueKey) return item.uniqueKey;
  const meta = item.metadata || {};
  return [
    item.type || 'notification',
    meta.alertId || item.alertId || '',
    meta.caseId || '',
    meta.step || meta.currentStep || '',
    item.status || 'unread'
  ].join('|');
}

function decorate(item) {
  return {
    ...item,
    displayTitle: formatTitle(item),
    displaySubtitle: formatSubtitle(item),
    displayDetail: item.detail || '',
    entityLabel: inferEntityLabel(item),
    caseLabel: inferCaseLabel(item),
    kindLabel: humanizeType(item.type),
    uniqueKey: uniqueKeyFor(item)
  };
}

function enqueue(tenantId, item) {
  const items = readStore(tenantId);
  const next = decorate({
    id: item.id || `n_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    status: 'unread',
    createdAt: new Date().toISOString(),
    ...item
  });
  items.unshift(next);
  writeStore(tenantId, items.slice(0, 500));
  return next;
}

function dedupeItems(items) {
  const grouped = new Map();
  for (const raw of items) {
    const item = decorate(raw);
    const key = item.uniqueKey;
    if (!grouped.has(key)) {
      grouped.set(key, { ...item, duplicateCount: 1, relatedIds: [item.id] });
      continue;
    }
    const current = grouped.get(key);
    grouped.set(key, {
      ...current,
      duplicateCount: (current.duplicateCount || 1) + 1,
      relatedIds: [...(current.relatedIds || []), item.id],
      createdAt: current.createdAt > item.createdAt ? current.createdAt : item.createdAt
    });
  }
  return Array.from(grouped.values()).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
}

function list(tenantId, { status, limit = 100, dedupe = false } = {}) {
  let items = readStore(tenantId).map(decorate);
  if (status) items = items.filter(i => i.status === status);
  if (dedupe) items = dedupeItems(items);
  return items.slice(0, limit);
}

function ack(tenantId, id, actor = 'system') {
  const items = readStore(tenantId);
  const idx = items.findIndex(i => i.id === id || (Array.isArray(i.relatedIds) && i.relatedIds.includes(id)));
  if (idx === -1) return null;
  const target = items[idx];
  const groupKey = uniqueKeyFor(target);
  const now = new Date().toISOString();
  const updated = items.map(item => {
    if (uniqueKeyFor(item) !== groupKey) return item;
    return { ...item, status: 'acked', ackedAt: now, ackedBy: actor };
  });
  writeStore(tenantId, updated);
  return decorate({ ...target, status: 'acked', ackedAt: now, ackedBy: actor });
}

function stats(tenantId) {
  const items = dedupeItems(readStore(tenantId));
  return {
    total: items.length,
    unread: items.filter(i => i.status !== 'acked').length,
    mentions: items.filter(i => i.type === 'mention').length,
    escalation: items.filter(i => i.type === 'sla-breach' || i.type === 'escalation').length,
    approvals: items.filter(i => i.type === 'approval').length
  };
}

module.exports = { enqueue, list, ack, stats, dedupeItems, decorate };
