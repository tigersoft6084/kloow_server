const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { execFile } = require('child_process');
const util = require('util');
const db = require('./database');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const { verifyToken, hashId, JWT_SECRET, JWT_REFRESH_SECRET } = require('./common');

const app = express();
const PORT = 8001;
const execFileAsync = util.promisify(execFile);

// Middleware
app.use(bodyParser.json({ limit: '10mb' })); // Limit payload size for security
app.use(express.urlencoded({ limit: '10mb', extended: true }));
app.use(
  cors({
    origin: 'https://admin.kloow.com', // Adjust to your frontend's domain/port
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

// update password endpoint. check the current password first
apiRouter.post('/update_password', verifyToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ message: 'Current and new passwords required' });
  }

  try {
    const user = await new Promise((resolve, reject) => {
      db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const isPasswordValid = await bcrypt.compare(currentPassword, user.password);
    if (!isPasswordValid) {
      return res.status(402).json({ message: 'Current password is incorrect' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET password = ? WHERE id = ?', [hashedNewPassword, req.user.id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    res.json({ message: 'Password updated successfully. Please log in again.' });
  } catch (error) {
    console.error('Update password error:', error);
    res.status(500).json({ message: 'Internal server error' });
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

// Get wordperss servers and their all memberships
apiRouter.get('/wordpress_memberships', verifyToken, async (req, res) => {
  try {
    const wordpressServers = await new Promise((resolve, reject) => {
      db.all(
        'SELECT id, domain, membership_key, type, is_active, created_at, updated_at FROM servers WHERE type = ?',
        ['wordpress'],
        (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        }
      );
    });

    const tmpResult = [];
    for (const server of wordpressServers) {
      try {
        const membershipResponse = await fetch(
          `https://${server.domain}/?ihc_action=api-gate&ihch=${server.membership_key}&action=list_levels`
        );
        const memberships = await membershipResponse.json();
        tmpResult.push({
          ...server,
          memberships: memberships.response || []
        });
      } catch (error) {
        console.log(error);
      }
    }

    const result = [];
    for (const serverData of tmpResult) {
      for (const membership in serverData.memberships) {
        result.push({
          server_id: serverData.id,
          domain: serverData.domain,
          is_active: serverData.is_active,
          membership_id: serverData.memberships[membership].level_id,
          membership_label: serverData.memberships[membership].label
        });
      }
    }

    res.json({ wordpress_memberships: result });
  } catch (error) {
    console.error('Get WordPress servers error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Get all allowed apps through all servers & membership plans
apiRouter.get('/allowed_apps', verifyToken, async (req, res) => {
  try {
    const allowed_apps = await new Promise((resolve, reject) => {
      db.all('SELECT id, server_name, membership_id, allowed_apps, frog FROM matchings', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    res.json({
      allowed_apps: allowed_apps.map((app) => {
        return {
          server_name: app.server_name,
          membership_id: parseInt(app.membership_id),
          allowed_apps: JSON.parse(app.allowed_apps),
          frog: app.frog === 1 ? true : false
        };
      }),
    });
  } catch (error) {
    console.error('Get allowed apps error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Update or insert allowed apps for the array of the server_name & membership_id and allowed_apps (admin only)
apiRouter.put('/allowed_apps', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { allowed_apps } = req.body;
  if (!Array.isArray(allowed_apps)) {
    return res.status(400).json({ message: 'Allowed apps array required' });
  }

  try {
    for (const app of allowed_apps) {
      const allowedAppsString = JSON.stringify(app.allowed_apps || []);
      const existingRecord = await new Promise((resolve, reject) => {
        db.get('SELECT id FROM matchings WHERE server_name = ? AND membership_id = ?', [app.server_name, app.membership_id], (err, row) => {
          if (err) reject(err);
          resolve(row);
        });
      });

      if (!existingRecord) {
        // Insert new record
        await new Promise((resolve, reject) => {
          db.run(
            'INSERT INTO matchings (server_name, membership_id, allowed_apps, frog) VALUES (?, ?, ?, ?)',
            [app.server_name, app.membership_id, allowedAppsString, app.frog],
            (err) => {
              if (err) reject(err);
              resolve();
            }
          );
        });
        continue;
      }

      // Update existing record
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE matchings SET allowed_apps = ?, frog = ? WHERE server_name = ? AND membership_id = ?',
          [allowedAppsString, app.frog, app.server_name, app.membership_id],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
    }

    const updatedAllowedApps = await new Promise((resolve, reject) => {
      db.all('SELECT id, server_name, membership_id, allowed_apps, frog FROM matchings', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    res.json({
      message: 'Allowed apps updated successfully',
      allowed_apps: updatedAllowedApps.map((app) => {
        return {
          server_name: app.server_name,
          membership_id: parseInt(app.membership_id),
          allowed_apps: JSON.parse(app.allowed_apps),
          frog: app.frog === 1 ? true : false
        };
      })
    });
  } catch (error) {
    console.error('Update allowed apps error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

apiRouter.get('/frog_versions', verifyToken, async (req, res) => {
  try {
    const frogVersions = await new Promise((resolve, reject) => {
      db.all('SELECT id, name, version FROM frog_version ORDER BY created_at DESC', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });
    console.log(frogVersions);
    res.json({ frog_versions: frogVersions });
  } catch (error) {
    console.error('Get frog versions error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

apiRouter.put('/frog_versions', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { frog_versions } = req.body;

  for (const fv of frog_versions) {
    const name = fv.name;
    const version = fv.version;

    if (!name || !version) {
      return res.status(400).json({ message: 'Name and version are required for all frog versions' });
    }

    if (!name || !version) {
      return res.status(400).json({ message: 'Name and version are required' });
    }

    try {
      // UPSERT (insert or update)
      await new Promise((resolve, reject) => {
        db.run(
          `
          INSERT INTO frog_version (name, version)
          VALUES (?, ?)
          ON CONFLICT(name) DO UPDATE SET
            version = excluded.version
          `,
          [name, version],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });

      const frogVersions = await new Promise((resolve, reject) => {
        db.all(
          'SELECT id, name, version FROM frog_version ORDER BY created_at DESC',
          [],
          (err, rows) => {
            if (err) reject(err);
            resolve(rows);
          }
        );
      });

      console.log(frogVersions);

      res.json({
        message: 'Frog version saved successfully',
        frog_versions: frogVersions
      });
    } catch (error) {
      console.error('Add frog version error:', error);
      res.status(500).json({ message: 'Internal server error' });
    }
  }
});


const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir);
}

// Serve uploaded files under /api/v1/uploads so same-origin requests get image content
apiRouter.use('/uploads', express.static(uploadDir));

// Mount the router with the prefix
app.use('/api/v1', apiRouter);

// Configure Multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname).toLowerCase());
  }
});

const upload = multer({
  storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    const filetypes = /jpeg|jpg|png|gif/;
    const extname = filetypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = filetypes.test(file.mimetype);
    if (extname && mimetype) return cb(null, true);
    cb(new Error('Images only!'));
  }
});

app.use('/uploads', express.static(uploadDir));

// Get uploaded images endpoint (admin only)
apiRouter.get('/images', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  try {
    const rows = await new Promise((resolve, reject) => {
      db.all('SELECT id, app_name, thumb_path, logo_path FROM server_images', [], (err, r) => {
        if (err) reject(err);
        resolve(r);
      });
    });
    const images = rows.map((row) => ({
      ...row,
      thumb_path: row.thumb_path?.startsWith('/uploads/') ? `/api/v1${row.thumb_path}` : row.thumb_path,
      logo_path: row.logo_path?.startsWith('/uploads/') ? `/api/v1${row.logo_path}` : row.logo_path
    }));
    res.json({ images });
  } catch (error) {
    console.error('Get images error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// Delete image entry and associated files (admin only)
apiRouter.delete('/images/:id', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { id } = req.params;

  try {
    // Step 1: Get image paths before deleting
    const image = await new Promise((resolve, reject) => {
      db.get('SELECT thumb_path, logo_path FROM server_images WHERE id = ?', [id], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });

    if (!image) {
      return res.status(404).json({ message: 'Image record not found' });
    }

    const deleteFile = (filePath) => {
      const rel = filePath?.replace(/^\/api\/v1\/uploads\//, '').replace(/^\/uploads\//, '') || path.basename(filePath);
      const fullPath = path.join(uploadDir, rel);
      if (fs.existsSync(fullPath)) {
        fs.unlink(fullPath, (err) => {
          if (err) console.error(`Failed to delete file: ${fullPath}`, err);
        });
      }
    };

    deleteFile(image.thumb_path);
    deleteFile(image.logo_path);

    // Step 3: Delete record from database
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM server_images WHERE id = ?', [id], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    // Step 4: Return updated image list
    const images = await new Promise((resolve, reject) => {
      db.all('SELECT id, app_name, thumb_path, logo_path FROM server_images', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    res.json({ message: 'Application deleted successfully', images });
  } catch (error) {
    console.error('Delete image error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Image upload endpoint (admin only)
apiRouter.post(
  '/upload_images',
  verifyToken,
  upload.fields([
    { name: 'thumbImage', maxCount: 1 },
    { name: 'logoImage', maxCount: 1 }
  ]),
  async (req, res) => {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: 'Admin access required' });
    }

    const { applicationName } = req.body;
    const thumbFile = req.files['thumbImage']?.[0];
    const logoFile = req.files['logoImage']?.[0];

    if (!applicationName || !thumbFile || !logoFile) {
      return res.status(400).json({ message: 'Server name, thumb image, and logo image are required' });
    }

    try {
      const thumbPath = `/api/v1/uploads/${thumbFile.filename}`;
      const logoPath = `/api/v1/uploads/${logoFile.filename}`;
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO server_images (app_name, thumb_path, logo_path) VALUES (?, ?, ?)',
          [applicationName, thumbPath, logoPath],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });

      const images = await new Promise((resolve, reject) => {
        db.all('SELECT id, app_name, thumb_path, logo_path FROM server_images', [], (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        });
      });
      res.json({ images });
    } catch (err) {
      console.error('Image upload error:', err);
      res.status(500).json({ status: false, message: 'Internal server error' });
    }
  }
);

// Get all application list endpoint
apiRouter.get('/app_list', verifyToken, async (req, res) => {
  // Step 1: Fetch app list from external API
  const response = await fetch('https://debicaserver.click/api/apps/get-all-apps', {
    method: 'GET',
    headers: { 'Content-Type': 'application/json' }
  });

  if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

  const data = await response.json();
  // Step 2: Return the app list
  res.json({ appList: data.appList });
});

// Normalize credentials to [username, password, domain_limit, keyword_limit]
function normalizeCredentials(creds) {
  if (!Array.isArray(creds)) return [];
  return creds.map((c) => {
    if (!Array.isArray(c) || c.length < 2) return c;
    return [c[0], c[1], c[2] ?? 0, c[3] ?? 0];
  });
}

// --- Helper function to build enriched app list ---
async function getAppListData(user) {
  const uid = user.id;
  const username = user.username;
  const role = user.is_admin ? "admin" : "user";

  const containers = await new Promise((resolve, reject) => {
    db.all('SELECT * FROM containers WHERE username = ? AND port != ?', [hashId(username), 0], (err, rows) =>
      err ? reject(err) : resolve(rows)
    );
  });

  // Step 1: Fetch app list from external API
  const response = await fetch('https://debicaserver.click/api/apps/get-apps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      rootUrl: "admin.kloow.com",
      id: uid,
      name: username,
      role
    })
  });

  if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

  const data = await response.json();
  const appList = (data.appList || []).filter((app) => app.account_pooling).map((app) => ({ ...app, port: 0 }));

  // Step 3: Merge everything
  let enrichedApps = [];
  for (const app of appList) {
    const matchedContainer = containers.find((row) => row.project_id === app.id);
    for (const server of app.servers) {
      const credentials = await new Promise((resolve, reject) => {
        db.all('SELECT * FROM account_info WHERE name = ? AND server_ip = ?', [app.title.toLowerCase(), server], (err, rows) =>
          err ? reject(err) : resolve(rows)
        );
      });

      const rawCreds = credentials[0] ? JSON.parse(credentials[0].credentials) : [];
      enrichedApps.push({
        id: app.id,
        title: app.title,
        server: server,
        credentials: normalizeCredentials(rawCreds),
        limitFields: app.limits,
        initUrl: app.initUrl,
        port: matchedContainer ? matchedContainer.port : 0
      });
    }
  }

  return enrichedApps;
}

// App list endpoint
apiRouter.get('/app_info', verifyToken, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      return res.status(403).json({ message: 'Admin access required' });
    }
    const appList = await getAppListData(req.user);
    res.json({ appList });
  } catch (error) {
    console.error(`Error fetching app list: ${error}`);
    res.status(500).json({ message: 'Failed to fetch app list' });
  }
});

// App list endpoint – update credentials for an account (body: title or name, server_ip, credentials)
apiRouter.put('/app_info', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { title, server_ip, credentials } = req.body;
  const accountName = title.toLowerCase();

  if (!accountName || !server_ip || !Array.isArray(credentials)) {
    return res.status(400).json({ message: 'title (or name), server_ip and credentials array required' });
  }

  try {
    const normalized = normalizeCredentials(credentials);
    const existing = await new Promise((resolve, reject) => {
      db.get('SELECT id FROM account_info WHERE name = ? AND server_ip = ?', [accountName, server_ip], (err, row) => {
        if (err) reject(err);
        resolve(row);
      });
    });
    if (existing) {
      await new Promise((resolve, reject) => {
        db.run(
          'UPDATE account_info SET credentials = ? WHERE name = ? AND server_ip = ?',
          [JSON.stringify(normalized), accountName, server_ip],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
    } else {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO account_info (name, server_ip, credentials) VALUES (?, ?, ?)',
          [accountName, server_ip, JSON.stringify(normalized)],
          (err) => {
            if (err) reject(err);
            resolve();
          }
        );
      });
    }

    const appList = await getAppListData(req.user);
    res.json({ message: 'Account info updated successfully', appList });
  } catch (error) {
    console.error('Update account info error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// App list endpoint – delete entire account_info row (body: title or name, server_ip)
apiRouter.delete('/app_info', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { title, server_ip } = req.body;
  const accountName = title.toLowerCase();

  if (!accountName || !server_ip) {
    return res.status(400).json({ message: 'title (or name) and server_ip required' });
  }

  try {
    await new Promise((resolve, reject) => {
      db.run('DELETE FROM account_info WHERE name = ? AND server_ip = ?', [accountName, server_ip], (err) => {
        if (err) reject(err);
        resolve();
      });
    });

    const appList = await getAppListData(req.user);
    res.json({ message: 'Account info deleted successfully', appList });
  } catch (error) {
    console.error('Delete account info error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Run app endpoint
apiRouter.post('/run_app', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  try {
    const { id, url, proxyServer } = req.body;
    const { username } = req.user;
    const tokenValue = url ? url.split("?")[1] : "";
    const freshUrl = `${url}&fresh=1`;

    const existing = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM containers WHERE username = ? and project_id = ? and port != ?',
        [hashId(username), id, 0],
        (err, row) => (err ? reject(err) : resolve(row))
      );
    });

    if (existing) {
      return res.status(500).json({ message: 'This application is already running.' });
    }

    const containers = await new Promise((resolve, reject) => {
      db.all('SELECT port FROM containers where port != 0', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    const usedPorts = new Set(containers.map((row) => row.port));

    let freePort = null;
    for (let port = 10000; port <= 10500; port++) {
      if (!usedPorts.has(port)) {
        freePort = port;
        break;
      }
    }

    if (!freePort) {
      return res.status(500).json({ message: 'No available ports in range.' });
    }

    let runStdout;
    try {
      const { stdout } = await execFileAsync('./kasm/run.sh', [
        `${hashId(username)}-${id}`,
        freshUrl,
        `http://${proxyServer}:3000`,
        String(freePort),
        tokenValue
      ]);
      runStdout = stdout.trim();
    } catch (err) {
      console.error(`Error running container: ${err.message}`);
      return res.status(500).json({ message: `Error running container: ${err.message}` });
    }

    const maybeRow = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM containers WHERE username = ? and project_id = ? and port = ?',
        [hashId(username), id, 0],
        (err, row) => (err ? reject(err) : resolve(row))
      );
    });

    if (maybeRow) {
      await new Promise((resolve, reject) => {
        db.run('UPDATE containers SET container_id = ?, port = ? WHERE id = ?', [runStdout, freePort, maybeRow.id], (err) =>
          err ? reject(err) : resolve()
        );
      });
    } else {
      await new Promise((resolve, reject) => {
        db.run(
          'INSERT INTO containers (username, project_id, container_id, port) VALUES (?, ?, ?, ?)',
          [hashId(username), id, runStdout, freePort],
          (err) => (err ? reject(err) : resolve())
        );
      });
    }

    return res.json({ success: true, freePort });
  } catch (error) {
    console.error(`Error run app: ${error.message}`);
    return res.status(500).json({ message: 'Failed to run app' });
  }
});

// Stop app endpoint
apiRouter.post('/stop_app', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  try {
    const { id } = req.body;
    const { username } = req.user;

    const row = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM containers WHERE username = ? and project_id = ? and port != ?',
        [hashId(username), id, 0],
        (err, row) => (err ? reject(err) : resolve(row))
      );
    });

    if (!row) {
      return res.status(404).json({ message: 'Application not found' });
    }

    try {
      await execFileAsync('./kasm/stop.sh', [row.container_id]);
    } catch (err) {
      console.error(`Error stopping app: ${err.message}`);
      return res.status(500).json({ message: `Error stopping app: ${err.message}` });
    }

    await new Promise((resolve, reject) => {
      db.run('UPDATE containers SET port = ? WHERE id = ?', [0, row.id], (err) => (err ? reject(err) : resolve()));
    });

    return res.json({ success: true });
  } catch (error) {
    console.error(`Error stop app: ${error.message}`);
    return res.status(500).json({ message: 'Failed to stop app' });
  }
});

apiRouter.post('/set', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { title, server_ip, old_username, new_username, password, limitsField } = req.body;

  if (!title || !server_ip || !password || limitsField === undefined) {
    return res.status(400).json({
      message: 'title, server_ip, password, and limitsField are required'
    });
  }

  const name = title.toLowerCase();

  try {
    const targetUrl = `http://${server_ip}:3000/set-seocromom-params?name=${name}&old_user=${old_username ?? ""}&new_user=${new_username ?? ""}`;

    const bodyParams = {}
    bodyParams[`${name}Username`] = new_username ?? "";
    bodyParams[`${name}Password`] = password;
    if (limitsField && typeof limitsField === 'object') {
      limitsField.forEach(limit => {
        bodyParams[`${limit.name}`] = limit.value;
      });
    }

    const response = await fetch(targetUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(bodyParams)
    });

    if (response.ok) {
      return res.status(200).json({
        message: 'Request forwarded',
        targetUrl
      });
    } else {
      return res.status(500).json({
        message: 'Please check proxy works now',
        targetUrl
      })
    }

  } catch (error) {
    console.error('Forward set params error:', error);
    return res.status(500).json({ message: 'Internal Server Error' });
  }
});

apiRouter.post('/credit', verifyToken, async (req, res) => {
  if (!req.user.is_admin) {
    return res.status(403).json({ message: 'Admin access required' });
  }

  const { title, server_ip, username } = req.body;

  if (!title || !server_ip || !username) {
    return res.status(400).json({ message: 'Title, Server IP, Username reqired'});
  }

  try {
    const targetUrl = `http://${server_ip}:3000/get-seocromom-credit?name=${title.toLowerCase()}&user=${username}`;

    const response = await fetch(targetUrl);
    const contentType = response.headers.get('content-type') || 'text/plain; charset=utf-8';
    const responseBody = await response.text();

    res.set('Content-Type', contentType);
    return res.status(response.status).send(responseBody);
  } catch (error) {
    console.error('Failed to get credit:', error);
    return res.status(500).json({ message: 'Internal Server Error'})
  }
})

// Error handling middleware
app.use((err, _req, res, _next) => {
  console.error(`Unhandled message: ${err.message}`);
  res.status(500).json({ message: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Proxy server running on http://127.0.0.1:${PORT}`);
});
