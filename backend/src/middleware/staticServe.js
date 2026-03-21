// Add this block to backend/src/index.js AFTER all API routes
// for production: serves the React frontend build from /public

const express = require('express');
const path = require('path');
const fs = require('fs');

function setupStaticServing(app) {
  const publicPath = path.join(__dirname, '../../public');
  const indexPath = path.join(publicPath, 'index.html');

  console.log('[STATIC] publicPath:', publicPath);
  console.log('[STATIC] index exists:', fs.existsSync(indexPath));

  app.use(express.static(publicPath));

  app.get('*', (req, res, next) => {
    if (req.path.startsWith('/api')) {
      return next();
    }

    if (fs.existsSync(indexPath)) {
      return res.sendFile(indexPath);
    }

    return res.status(404).send('Frontend build not found');
  });
}

module.exports = { setupStaticServing };
