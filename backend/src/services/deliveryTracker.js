const fs = require('fs');
const path = require('path');

const DIR = process.env.NODE_ENV === 'production' ? '/home/delivery-tracker' : path.join(__dirname, '../../../delivery-tracker');
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

function track(tenantId, event) {
  const items = readStore(tenantId);
  const next = {
    id: event.id || `d_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`,
    createdAt: new Date().toISOString(),
    status: 'queued',
    channel: 'inbox',
    ...event
  };
  items.unshift(next);
  writeStore(tenantId, items.slice(0, 500));
  return next;
}

function list(tenantId, { channel, status, limit = 100 } = {}) {
  let items = readStore(tenantId);
  if (channel) items = items.filter(i => i.channel === channel);
  if (status) items = items.filter(i => i.status === status);
  return items.slice(0, limit);
}

function stats(tenantId) {
  const items = readStore(tenantId);
  const by = (field, value) => items.filter(i => i[field] === value).length;
  return {
    total: items.length,
    queued: by('status', 'queued'),
    delivered: by('status', 'delivered'),
    failed: by('status', 'failed'),
    inbox: by('channel', 'inbox'),
    email: by('channel', 'email'),
    telegram: by('channel', 'telegram')
  };
}

module.exports = { track, list, stats };
