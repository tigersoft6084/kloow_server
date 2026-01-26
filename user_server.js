const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const { exec } = require('child_process');
const jwt = require('jsonwebtoken');
const util = require('util');

const db = require('./database');
const { verifyToken, fetchUserData, hashId, JWT_SECRET, JWT_REFRESH_SECRET } = require('./common');

const execAsync = util.promisify(exec);
const app = express();
const PORT = 3001;

// Middleware
app.use(bodyParser.json({ limit: '10kb' })); // Limit payload size for security
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

    let servers = await new Promise((resolve, reject) => {
      db.all('SELECT domain, membership_key FROM servers where is_active = 1 and type = "wordpress"', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    let userRole = 'user';
    let membershipInfo = [];
    for (const server of servers) {
      const { domain, membership_key } = server;
      if (domain && membership_key) {
        const maserverResult = await fetchUserData(log, pwd, domain, membership_key);
        if (maserverResult.success) {
          const { uid, username, role, membershipDetails } = maserverResult.user;
          membershipInfo.push({ uid, username, role, domain, membershipDetails, type: 'wordpress' });
          if (role === 'admin') {
            userRole = 'admin';
          }
        }
      }
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
          const membershipDetails = [
            {
              level_id: 0,
              label: 'Kloow',
              expire_time: '2100-12-31 23:59:59'
            }
          ]
          const username = log;
          if (loginResult?.user?.role === 'admin') {
            userRole = 'admin'
          }
          membershipInfo.push({ uid, username, role: loginResult?.user?.role ?? 'user', domain, membershipDetails, type: 'nextjs' });
        }
      }
    }

    if (membershipInfo.length > 0) {
      const accessToken = jwt.sign(
        { username: log, role: userRole, membershipInfo },
        JWT_SECRET,
        {
          expiresIn: '15m'
        }
      );

      const refreshToken = jwt.sign(
        { username: log, role: userRole, membershipInfo },
        JWT_REFRESH_SECRET,
        {
          expiresIn: '7d'
        }
      );

      const result = {
        authentication_success: true,
        accessToken,
        refreshToken,
        user: { username: log, role: userRole, membershipInfo }
      }
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

    const { username, role, membershipInfo } = decoded;

    const newMembershipInfo = membershipInfo
      .map(member => {
        // Filter out expired memberships
        const filteredDetails = member.membershipDetails.filter(
          m => new Date(m.expire_time) >= new Date()
        );

        return {
          ...member,
          membershipDetails: filteredDetails,
        };
      })
      // Remove members with no valid membership left
      .filter(member => member.membershipDetails.length > 0);

    if (newMembershipInfo.length <= 0) {
      return res.status(403).json({ message: 'Membership is expired. Please renew your subscription.' });
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { username, role, membershipInfo: newMembershipInfo },
      JWT_SECRET,
      {
        expiresIn: '15m'
      }
    );

    res.json({
      authentication_success: true,
      accessToken: newAccessToken,
      user: { username, role, membershipInfo: newMembershipInfo }
    });
  } catch (error) {
    console.error('Refresh token verification message:', error);
    res.status(402).json({ message: 'Invalid or expired refresh token' });
  }
});

// --- Helper function to build enriched app list ---
async function getAppListData(user) {
  const { username, role, membershipInfo } = user;

  let allowed_apps = [];

  const [containers, images, logs, favorites] = await Promise.all([
    new Promise((resolve, reject) => {
      db.all('SELECT * FROM containers WHERE username = ? AND port != ?', [hashId(username), 0], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT app_name, thumb_path, logo_path FROM server_images', [], (err, rows) => (err ? reject(err) : resolve(rows)));
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT project_id, updated_at FROM logs WHERE username = ?', [hashId(username)], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
    new Promise((resolve, reject) => {
      db.all('SELECT project_id FROM favorites WHERE username = ?', [hashId(username)], (err, rows) =>
        err ? reject(err) : resolve(rows)
      );
    }),
  ]);

  let wholeAppList = [];
  await Promise.all(
    membershipInfo.map(async membershipData => {
      const { uid, username, role, domain, membershipDetails, type } = membershipData;

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
      wholeAppList = Array.from(
        new Map(
          [...wholeAppList, ...appList].map(app => [app.title, app])
        ).values()
      );

      // Step 2: Fetch DB data

      if (type === 'wordpress') {
        await Promise.all(
          membershipDetails.map(async (membership) => {
            const membership_allowed_apps = await new Promise((resolve, reject) => {
              db.get('SELECT allowed_apps FROM matchings WHERE server_name = ? AND membership_id = ?', [domain, membership.level_id], (err, row) =>
                err ? reject(err) : resolve(row ? JSON.parse(row.allowed_apps) : [])
              );
            });
            allowed_apps.push(...membership_allowed_apps);
          })
        );
      } else {
        allowed_apps = Array.from(
          new Set([
            ...allowed_apps,
            ...appList.map(app => app.title)
          ])
        );
      }
    })
  );

  // Step 3: Merge everything
  const enrichedApps = wholeAppList.map((app) => {
    const matchedContainer = containers.find((row) => row.project_id === app.id);
    const matchedImage = images.find((img) => img.app_name === app.title);
    const matchLog = logs.find((log) => log.project_id === app.id);
    const isFavorite = favorites.find((log) => log.project_id === app.id);
    app.initUrl = role === 'admin' ? app.initUrl : allowed_apps.includes(app.title) ? app.initUrl : '';

    return {
      ...app,
      port: matchedContainer ? matchedContainer.port : 0,
      thumbPath: matchedImage ? matchedImage.thumb_path : '',
      logoPath: matchedImage ? matchedImage.logo_path : '',
      lastAccessed: matchLog ? matchLog.updated_at : null,
      isFavorite: !!isFavorite,
      isAllowed: role === 'admin' ? true : allowed_apps.includes(app.title)
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
    console.error(`Error fetching app list: ${error}`);
    res.status(500).json({ message: 'Failed to fetch app list' });
  }
});

apiRouter.post('/check-seocromom-health', verifyToken, async (req, res) => {
  const healthStatuses = {};
  const { role } = req.user;
  const { serverSelection } = req.body;

  for (const appId of Object.keys(serverSelection)) {
    const serverIp = serverSelection[appId];

    try {
      const response = await fetch(`http://${serverIp}:3000/check-seocromom-health`);

      if (!response.ok) {
        throw new Error(`Health check failed for ${appId}`);
      }

      // Admins always see healthy
      if (role === 'admin') {
        healthStatuses[appId] = true;
        continue;
      }

      const data = await response.json();

      let healthStatus = Boolean(data.mongodb_status) && Boolean(data.login_status);

      if (typeof data.subscription_status === 'boolean') {
        healthStatus = healthStatus && data.subscription_status;
      }

      healthStatuses[appId] = healthStatus;
    } catch (error) {
      healthStatuses[appId] = false;
    }
  }

  res.json({ healthStatuses });
});

apiRouter.get('/frog_status', verifyToken, async (req, res) => {
  try {
    const { role, membershipInfo } = req.user;

    let frog = false;

    if (role === "admin") {
      frog = true;
    } else {
      // Collect promises
      const promises = [];

      for (const membershipData of membershipInfo) {
        const { domain, membershipDetails } = membershipData;

        for (const membership of membershipDetails) {
          const p = new Promise((resolve, reject) => {
            db.get(
              'SELECT frog FROM matchings WHERE server_name = ? AND membership_id = ?',
              [domain, membership.level_id],
              (err, row) => {
                if (err) return reject(err);

                if (row?.frog === 1) frog = true;
                resolve();
              }
            );
          });

          promises.push(p);
        }
      }

      // Wait for all DB queries
      await Promise.all(promises);
    }

    if (frog) {
      const frogVersions = await new Promise((resolve, reject) => {
        db.all('SELECT id, name, version FROM frog_version ORDER BY created_at DESC', [], (err, rows) => {
          if (err) reject(err);
          resolve(rows);
        });
      });

      let frog_versions = {};
      frogVersions.forEach(frogVersion => {
        frog_versions[frogVersion.name] = frogVersion.version;
      });

      return res.json({ frog: frog_versions })
    } else {
      return res.json({ frog: { seo_spider: null, log_analyser: null } })
    }
  } catch (error) {
    console.error(`Error fetching frog status: ${error.message}`);
    return res.status(500).json({ message: 'Failed to fetch frog status' });
  }
});

// Run app endpoint
apiRouter.post('/run_app', verifyToken, async (req, res) => {
  try {
    const { id, url, proxyServer } = req.body;
    const { username } = req.user;
    // check for an already running container
    const existing = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM containers WHERE username = ? and project_id = ? and port != ?',
        [hashId(username), id, 0],
        (err, row) => (err ? reject(err) : resolve(row))
      );
    });

    console.log('Existing container check:', existing);

    if (existing) {
      return res.status(500).json({ message: 'This application is already running.' });
    }

    // Get all current running ports
    let containers = await new Promise((resolve, reject) => {
      db.all('SELECT port FROM containers where port != 0', [], (err, rows) => {
        if (err) reject(err);
        resolve(rows);
      });
    });

    // Convert DB rows → Set for fast lookup
    const usedPorts = new Set(containers.map((row) => row.port));

    // Find an available port
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
      const cmd = [`${hashId(username)}-${id}`, `"${url}"`, `http://${proxyServer}:3000`, freePort].join(' ');
      const { stdout } = await execAsync(`./kasm/run.sh ${cmd}`);
      runStdout = stdout.trim();
    } catch (err) {
      console.error(`Error running container: ${err.message}`);
      return res.status(500).json({ message: `Error running container: ${err.message}` });
    }

    console.log('Container run succeeded with ID:', runStdout);

    // Insert or update the DB record (find row with port = 0)
    const maybeRow = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM containers WHERE username = ? and project_id = ? and port = ?',
        [hashId(username), id, 0],
        (err, row) => (err ? reject(err) : resolve(row))
      );
    });

    console.log('Database record check (port=0):', maybeRow);

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

    console.log('Running container check:', row);

    // SECOND: stop the container
    try {
      await execAsync(`./kasm/stop.sh ${row.container_id}`);
    } catch (err) {
      console.error(`Error stopping app: ${err.message}`);
      return res.status(500).json({ message: `Error stopping app: ${err.message}` });
    }

    console.log('Container stop succeeded for ID:', row.container_id);

    // mark as stopped in DB (port -> 0)
    await new Promise((resolve, reject) => {
      db.run('UPDATE containers SET port = ? WHERE id = ?', [0, row.id], (err) => (err ? reject(err) : resolve()));
    });

    console.log('Database updated to mark container as stopped for ID:', row.id);

    return res.json({ success: true });
  } catch (error) {
    console.error(`Error stop app: ${error.message}`);
    return res.status(500).json({ message: 'Failed to stop app' });
  }
});

// logs endpoint
apiRouter.post('/logs', verifyToken, async (req, res) => {
  try {
    const { id } = req.body;
    const { username } = req.user;
    const now = new Date().toISOString();

    // Step 1: Update or insert log
    await new Promise((resolve, reject) => {
      db.get('SELECT * FROM logs WHERE username = ? AND project_id = ?', [hashId(username), id], (err, row) => {
        if (err) return reject(err);
        if (row) {
          db.run('UPDATE logs SET updated_at = ? WHERE id = ?', [now, row.id], (err) => (err ? reject(err) : resolve()));
        } else {
          db.run(
            'INSERT INTO logs (username, project_id, updated_at) VALUES (?, ?, ?)',
            [hashId(username), id, now],
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
    const { username } = req.user;

    // Step 1: Toggle favorite (add if not exist, remove if exists)
    const isFavorite = await new Promise((resolve, reject) => {
      db.get(
        'SELECT * FROM favorites WHERE username = ? AND project_id = ?',
        [hashId(username), id],
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
            db.run('INSERT INTO favorites (username, project_id) VALUES (?, ?, ?)', [hashId(username), id], (err) => {
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
