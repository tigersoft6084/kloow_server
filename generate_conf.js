const fs = require('fs');
const path = require('path');
const util = require('util');
const exec = util.promisify(require('child_process').exec);

const TEMPLATE_PATH = './kasm/nginx_config.conf';
const OUTPUT_DIR = '/etc/nginx/sites-enabled';
const DOMAIN = 'kloow.com';

async function generateConfigs() {
  // read once and keep originalTemplate unchanged
  const originalTemplate = fs.readFileSync(TEMPLATE_PATH, 'utf8');

  for (let port = 10000; port <= 10500; port++) {
    // create a fresh config string for each port
    const config = originalTemplate.replace(/GENERIC-PORT/g, String(port)).replace(/GENERIC-DOMAIN/g, DOMAIN);

    const filename = path.join(OUTPUT_DIR, `${DOMAIN}-${port}.conf`);
    fs.writeFileSync(filename, config, { encoding: 'utf8' });
    console.log(`Generated: ${filename}`);
  }

  console.log('All configs written. Testing nginx...');

  try {
    await exec('nginx -t');
    console.log('Nginx test OK. Restarting...');
    await exec('systemctl restart nginx'); // restart is less disruptive than restart
    console.log('Nginx restarted successfully!');
  } catch (err) {
    console.error('Nginx error:', err.stdout || err.stderr || err);
    process.exit(1);
  }
}

generateConfigs().catch((err) => {
  console.error('Failed:', err);
  process.exit(1);
});
