const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const db = require('./database');

const { verifyToken, JWT_SECRET, JWT_REFRESH_SECRET } = require('./common');

const app = express();
const PORT = 8001;

// Middleware
app.use(bodyParser.json({ limit: '1kb' })); // Limit payload size for security
app.use(
  cors({
    origin: 'http://46.62.137.213:8000', // Adjust to your frontend's domain/port
    credentials: true
  })
);
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} request to ${req.path}`);
  next();
});

// Create a router
const apiRouter = express.Router();

// Login endpoint
apiRouter.post('/login', async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ message: 'Username and password required' });
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      return res.status(402).json({ message: 'Invalid credentials' });
    }

    // Verify password using bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(402).json({ message: 'Invalid credentials' });
    }

    if (user.is_admin === 0) {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const accessToken = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '15m' });
    const refreshToken = jwt.sign({ id: user.id }, JWT_REFRESH_SECRET, { expiresIn: '7d' });

    res.json({ accessToken, refreshToken });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Refresh token endpoint
apiRouter.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'Refresh token required' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [decoded.id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      return res.status(402).json({ message: 'Invalid refresh token' });
    }

    const accessToken = jwt.sign({ id: user.id, username: user.username, is_admin: user.is_admin }, JWT_SECRET, { expiresIn: '15m' });
    res.json({ accessToken });
  } catch (error) {
    res.status(402).json({ message: 'Invalid or expired refresh token' });
  }
});

// Add server endpoint (admin only)
apiRouter.post('/servers', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { domain, membership_key, type } = req.body;
  if (!domain || !membership_key || !type) {
    return res.status(400).json({ message: 'Domain, membership api key, and type required' });
  }

  try {
    const server = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM servers WHERE domain = ?', [domain], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (server) {
      return res.status(400).json({ message: 'Server with this domain already exists' });
    }

    await new Promise((resolve, reject) => {
      db.run('INSERT INTO servers (domain, membership_key, type) VALUES (?, ?, ?)', [domain, membership_key, type], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, domain, membership_key, type, is_active, created_at, updated_at FROM servers', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.status(201).json({ message: 'Server added successfully', servers });
  } catch (error) {
    console.error('Add server error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update server endpoint (admin only)
apiRouter.put('/servers/:id', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { id } = req.params;
  const { domain, membership_key, is_active } = req.body;

  if (!domain && !membership_key && is_active === undefined) {
    return res.status(400).json({ message: 'At least one field required for update' });
  }

  try {
    const updates = [];
    const values = [];

    if (domain) {
      updates.push('domain = ?');
      values.push(domain);
    }
    if (membership_key) {
      updates.push('membership_key = ?');
      values.push(membership_key);
    }
    if (is_active !== undefined) {
      updates.push('is_active = ?');
      values.push(is_active ? 1 : 0);
    }

    values.push(id);

    await new Promise((resolve, reject) => {
      db.run(`UPDATE servers SET ${updates.join(', ')} WHERE id = ?`, values, (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, domain, membership_key, type, is_active, created_at, updated_at FROM servers', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json({ message: 'Server updated successfully', servers });
  } catch (error) {
    console.error('Update server error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Delete server endpoint (admin only)
apiRouter.delete('/servers/:id', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { id } = req.params;

  try {
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM servers WHERE id = ?', [id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, domain, membership_key, type, is_active, created_at, updated_at FROM servers', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json({ message: 'Server deleted successfully', servers });
  } catch (error) {
    console.error('Delete server error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get server list endpoint
apiRouter.get('/servers', verifyToken, async (req, res) => {
  try {
    const servers = await new Promise((resolve, reject) => {
      db.all('SELECT id, domain, membership_key, type, is_active, created_at, updated_at FROM servers', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json({ servers });
  } catch (error) {
    console.error('Get servers error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Mount the router with the prefix
app.use('/api/v1', apiRouter);

// Error handling middleware
app.use((err, _req, res, _next) => {
  console.error(`Unhandled message: ${err.message}`);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Proxy server running on http://localhost:${PORT}`);
});
