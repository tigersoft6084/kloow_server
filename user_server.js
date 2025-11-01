const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');

const db = require('./database');
const { verifyToken, fetchUserData, hashId, JWT_SECRET, JWT_REFRESH_SECRET } = require('./common');

const app = express();
const PORT = 3001;

// Middleware
app.use(bodyParser.json({ limit: '1kb' })); // Limit payload size for security
app.use(
  cors({
    origin: 'https://kloow.com', // Adjust to your frontend's domain/port
    credentials: true
  })
);
app.use((req, _res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} request to ${req.path}`);
  next();
});

// Create a router
const apiRouter = express.Router();

// Updated login endpoint to return JWT tokens in response
apiRouter.post('/login', async (req, res) => {
  try {
    const { log, pwd } = req.body;
    if (!log || !pwd) {
      return res.status(400).json({ message: 'Missing required fields: username or password' });
    }

    let result = null;

    let servers = await new Promise((resolve, reject) => {
      db.all('SELECT domain, membership_key FROM servers where is_active = 1 and type = "wordpress"', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    for (const server of servers) {
      const { domain, membership_key } = server;
      if (domain && membership_key) {
        const maserverResult = await fetchUserData(log, pwd, domain, membership_key);
        if (maserverResult.success) {
          const { uid, username, role, membership_name, membership_expire_time } = maserverResult.user;
          // Generate access token
          const accessToken = jwt.sign(
            { uid, username, role, domain, membership_name, membership_expire_time, type: 'wordpress' },
            JWT_SECRET,
            {
              expiresIn: '15m'
            }
          );

          // Generate refresh token
          const refreshToken = jwt.sign(
            { uid, username, role, domain, membership_name, membership_expire_time, type: 'wordpress' },
            JWT_REFRESH_SECRET,
            {
              expiresIn: '7d'
            }
          );
          result = {
            authentication_success: true,
            accessToken,
            refreshToken,
            user: { uid, username, role, domain, membership_name, membership_expire_time, type: 'wordpress' }
          };
        }
      }
    }

    if (result) {
      res.json(result);
      return;
    }

    servers = await new Promise((resolve, reject) => {
      db.all('SELECT domain FROM servers where is_active = 1 and type = "nextjs"', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    for (const server of servers) {
      const { domain } = server;
      if (domain) {
        const loginResponse = await fetch(`https://${domain}/api/users/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ email: log, password: pwd })
        });

        const loginResult = await loginResponse.json();

        if (loginResult?.token) {
          const uid = loginResult?.user?.id;
          const username = log;
          const membership_expire_time = '2100-12-31 23:59:59';
          // Generate access token
          const accessToken = jwt.sign({ uid, username, role: 'user', domain, membership_expire_time, type: 'nextjs' }, JWT_SECRET, {
            expiresIn: '15m'
          });

          // Generate refresh token
          const refreshToken = jwt.sign(
            { uid, username, role: 'user', domain, membership_expire_time, type: 'nextjs' },
            JWT_REFRESH_SECRET,
            {
              expiresIn: '7d'
            }
          );
          result = {
            authentication_success: true,
            accessToken,
            refreshToken,
            user: { uid, username, role: 'user', domain, membership_expire_time, type: 'nextjs' }
          };
        }
      }
    }

    if (result) {
      res.json(result);
    } else {
      res.status(404).json({ message: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Login message:', error);
    res.status(500).json({ message: 'Server error during authentication' });
  }
});

// Updated refresh token endpoint to accept refresh token in body and return new access token
apiRouter.post('/refresh-token', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ message: 'No refresh token provided' });
  }

  try {
    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);

    const { uid, username, role, domain, membership_name, membership_expire_time, type } = decoded;

    if (new Date(membership_expire_time) < new Date()) {
      return res.status(403).json({ message: 'Membership is expired. Please renew your subscription.' });
    }

    // Generate new access token
    const newAccessToken = jwt.sign({ uid, username, role, domain, membership_name, membership_expire_time, type }, JWT_SECRET, {
      expiresIn: '15m'
    });

    res.json({
      authentication_success: true,
      accessToken: newAccessToken,
      user: { uid, username, domain, membership_expire_time, type }
    });
  } catch (error) {
    console.error('Refresh token verification message:', error);
    res.status(402).json({ message: 'Invalid or expired refresh token' });
  }
});

// --- Helper function to build enriched app list ---
async function getAppListData(user) {
  const { username, domain, membership_name, type, role, uid } = user;

  // Step 1: Fetch app list from external API
  const response = await fetch('https://debicaserver.click/api/apps/get-apps', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      rootUrl: type === 'wordpress' ? domain : null,
      id: uid,
      name: username,
      role
    })
  });

  if (!response.ok) throw new Error(`HTTP error! Status: ${response.status}`);

  const data = await response.json();
  const appList = (data.appList || []).map((app) => ({ ...app, port: 0 }));

  // Step 2: Fetch DB data
  const [containers, images, logs, favorites, allowed_apps] = await Promise.all([
    new Promise((resolve, reject) => {
      db.all('SELECT * FROM containers WHERE username = ? AND auth_server = ? AND port != ?', [hashId(username), domain, 0], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT app_name, thumb_path, logo_path FROM server_images', [], (err, rows) => (err ? reject(err) : resolve(rows)));
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT project_id, updated_at FROM logs WHERE username = ? AND auth_server = ?', [hashId(username), domain], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT project_id FROM favorites WHERE username = ? AND auth_server = ?', [hashId(username), domain], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
    new Promise((resolve, reject) => {
      db.get('SELECT allowed_apps FROM matchings WHERE server_name = ? AND membership_plan = ?', [domain, membership_name], (err, row) =>
        err ? reject(err) : resolve(row ? JSON.parse(row.allowed_apps) : [])
      );
    })
  ]);

  // Step 3: Merge everything
  const enrichedApps = appList.map((app) => {
    const matchedContainer = containers.find((row) => row.project_id === app.id);
    const matchedImage = images.find((img) => img.app_name === app.title);
    const matchLog = logs.find((log) => log.project_id === app.id);
    const isFavorite = favorites.find((log) => log.project_id === app.id);

    return {
      ...app,
      domain,
      port: matchedContainer ? matchedContainer.port : 0,
      thumbPath: matchedImage ? matchedImage.thumb_path : '',
      logoPath: matchedImage ? matchedImage.logo_path : '',
      lastAccessed: matchLog ? matchLog.updated_at : null,
      isFavorite: !!isFavorite,
      isAllowed: type === 'wordpress' ? (role === 'admin' ? true : allowed_apps.includes(app.title)) : true
    };
  });

  return enrichedApps;
}

// App list endpoint
apiRouter.get('/app_list', verifyToken, async (req, res) => {
  try {
    const appList = await getAppListData(req.user);
    res.json({ appList });
  } catch (error) {
    console.error(`Error fetching app list: ${error.message}`);
    res.status(500).json({ message: 'Failed to fetch app list' });
  }
});

// Run app endpoint
apiRouter.post('/run_app', verifyToken, async (req, res) => {
  try {
    const { id, url, proxyServer } = req.body;
    const { username, domain } = req.user;
    const { default: getPort, portNumbers } = await import('get-port');
    const port = await getPort({ port: portNumbers(10000, 32767) });

    db.get(
      'SELECT * FROM containers WHERE username = ? and auth_server = ? and project_id = ? and port != ?',
      [hashId(username), domain, id, 0],
      (err, row) => {
        if (err) return res.status(500).json({ message: err.message });
        if (row) return res.status(500).json({ message: 'This application is already running.' });

        exec(
          `./kasm/run.sh ${[`${hashId(username)}-${domain}-${id}`, `"${url}"`, `http://${proxyServer}:3000`, port].join(' ')}`,
          (error, stdout, stderr) => {
            if (error) return res.status(500).json({ message: error.message });

            db.get(
              'SELECT * FROM containers WHERE username = ? and auth_server = ? and project_id = ? and port = ?',
              [hashId(username), domain, id, 0],
              (err, row) => {
                if (err) return res.status(500).json({ message: err.message });
                if (row) {
                  db.run('UPDATE containers SET container_id = ?, port = ? WHERE id = ?', [stdout.trim(), port, row.id], (err) => {
                    if (err) return res.status(500).json({ message: err.message });
                    res.json({ success: true, port });
                  });
                } else {
                  db.run(
                    'INSERT INTO containers (username, auth_server, project_id, container_id, port) VALUES (?, ?, ?, ?, ?)',
                    [hashId(username), domain, id, stdout.trim(), port],
                    (err) => {
                      if (err) return res.status(500).json({ message: err.message });
                      res.json({ success: true, port });
                    }
                  );
                }
              }
            );
          }
        );
      }
    );
  } catch (error) {
    console.error(`Error run app: ${error.message}`);
    res.status(500).json({ message: 'Failed to run app' });
  }
});

// Stop app endpoint
apiRouter.post('/stop_app', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;
    const { username, domain } = req.user;
    db.get(
      'SELECT * FROM containers WHERE username = ? and auth_server = ? and project_id = ? and port != ?',
      [hashId(username), domain, id, 0],
      (err, row) => {
        if (err) return res.status(500).json({ message: err.message });
        if (!row) return res.status(404).json({ message: 'Application not found' });

        exec(`./kasm/stop.sh ${row.container_id}`, (error, stdout, stderr) => {
          if (error) {
            console.error(`Error stopping app: ${error.message}`);
            return res.status(500).json({ message: `Error stopping app: ${error.message}` });
          }

          db.run('UPDATE containers SET port = ? WHERE id = ?', [0, row.id], (err) => {
            if (err) return res.status(500).json({ message: err.message });
            res.json({ success: true });
          });
        });
      }
    );
  } catch (error) {
    console.error(`Error stop app: ${error.message}`);
    res.status(500).json({ message: 'Failed to stop app' });
  }
});

// logs endpoint
apiRouter.post('/logs', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;
    const { username, domain } = req.user;
    const now = new Date().toISOString();

    // Step 1: Update or insert log
    await new Promise((resolve, reject) => {
      db.get('SELECT * FROM logs WHERE username = ? AND auth_server = ? AND project_id = ?', [hashId(username), domain, id], (err, row) => {
        if (err) return reject(err);
        if (row) {
          db.run('UPDATE logs SET updated_at = ? WHERE id = ?', [now, row.id], (err) => (err ? reject(err) : resolve()));
        } else {
          db.run(
            'INSERT INTO logs (username, auth_server, project_id, updated_at) VALUES (?, ?, ?, ?)',
            [hashId(username), domain, id, now],
            (err) => (err ? reject(err) : resolve())
          );
        }
      });
    });

    // Step 2: Fetch updated app list
    const appList = await getAppListData(req.user);

    // Step 3: Return success + updated list
    res.json({ success: true, appList });
  } catch (error) {
    console.error(`Error updating logs: ${error.message}`);
    res.status(500).json({ message: 'Failed to update logs or fetch app list' });
  }
});

// favorites endpoint
apiRouter.post('/favorites', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;
    const { username, domain } = req.user;
    const now = new Date().toISOString();

    // Step 1: Toggle favorite (add if not exist, remove if exists)
    const isFavorite = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM favorites WHERE username = ? AND auth_server = ? AND project_id = ?',
        [hashId(username), domain, id],
        (err, row) => {
          if (err) return reject(err);

          if (row) {
            // Exists — remove it
            db.run('DELETE FROM favorites WHERE id = ?', [row.id], (err) => {
              if (err) return reject(err);
              resolve(false); // Removed
            });
          } else {
            // Doesn't exist — add it
            db.run('INSERT INTO favorites (username, auth_server, project_id) VALUES (?, ?, ?)', [hashId(username), domain, id], (err) => {
              if (err) return reject(err);
              resolve(true); // Added
            });
          }
        }
      );
    });

    // Step 2: Fetch updated app list
    const appList = await getAppListData(req.user);

    // Step 3: Return success + updated list + state info
    res.json({
      success: true,
      message: isFavorite ? 'Added to favorites' : 'Removed from favorites',
      appList
    });
  } catch (error) {
    console.error(`Error updating favorites: ${error.message}`);
    res.status(500).json({ message: 'Failed to update favorites or fetch app list' });
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
  console.log(`Proxy server running on http://127.0.0.1:${PORT}`);
});
