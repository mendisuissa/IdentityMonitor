const fs = require('fs');
const path = require('path');

const DIRS = {
  settings: process.env.NODE_ENV === 'production' ? '/home/settings' : path.join(__dirname, '../../../settings'),
  audit: process.env.NODE_ENV === 'production' ? '/home/audit' : path.join(__dirname, '../../../audit'),
  workflows: process.env.NODE_ENV === 'production' ? '/home/workflows' : path.join(__dirname, '../../../workflows')
};

function collectIdsFromDir(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter(name => name.endsWith('.json') || name.endsWith('.jsonl'))
    .map(name => name.replace(/\.jsonl?$/, ''));
}

function getAllTenantIds() {
  return Array.from(new Set([
    ...collectIdsFromDir(DIRS.settings),
    ...collectIdsFromDir(DIRS.audit),
    ...collectIdsFromDir(DIRS.workflows)
  ])).filter(Boolean);
}

module.exports = { getAllTenantIds };
