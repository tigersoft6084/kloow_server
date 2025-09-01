const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const db = new sqlite3.Database('./db/data.db', (err) => {
  if (err) console.error('DB open error:', err.message);
  else console.log('Connected to SQLite');
});

db.serialize(() => {
  // Create users table
  db.run(
    `
      CREATE TABLE IF NOT EXISTS users (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL UNIQUE,
          password TEXT NOT NULL CHECK(length(password) <= 60),
          is_admin INTEGER DEFAULT 0,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `,
    (err) => {
      if (err) {
        console.error('Error creating users table:', err.message);
      } else {
        console.log('Users table initialized');
        // Insert default admin user
        bcrypt.hash('@dm!n', 10, (err, hashedPassword) => {
          if (err) {
            console.error('Error hashing admin password:', err.message);
            return;
          }
          db.run(
            `
              INSERT OR IGNORE INTO users (username, password, is_admin)
              VALUES (?, ?, 1)
            `,
            ['admin', hashedPassword],
            (err) => {
              if (err) {
                console.error('Error creating default admin user:', err.message);
              } else {
                console.log('Default admin user initialized');
              }
            }
          );
        });
      }
    }
  );

  // Create servers table
  db.run(
    `
      CREATE TABLE IF NOT EXISTS servers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          domain TEXT NOT NULL,
          membership_key TEXT NOT NULL,
          type TEXT NOT NULL,
          is_active INTEGER DEFAULT 1,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `,
    (err) => {
      if (err) {
        console.error('Error creating servers table:', err.message);
      } else {
        console.log('Servers table initialized');
      }
    }
  );

  db.run(
    `
      CREATE TABLE IF NOT EXISTS containers (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          username TEXT NOT NULL,
          auth_server TEXT NOT NULL,
          project_id TEXT NOT NULL,
          container_id TEXT NOT NULL,
          port INTEGER NOT NULL DEFAULT 0
      )
    `,
    (err) => {
      if (err) {
        console.error('Error creating containers table:', err.message);
      } else {
        console.log('Containers table initialized');
      }
    }
  );
});

module.exports = db;
