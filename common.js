const setCookie = require('set-cookie-parser');
const { load } = require('cheerio');
const { stringify } = require('qs');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'proxyservicejwttoken';
const JWT_REFRESH_SECRET = 'proxyservicejwtrefreshtoken';

const FUNCTION_CONTENT =
  '\n' +
  "add_action('rest_api_init', function () {\n" +
  "    register_rest_route('custom/v1', '/login/', array(\n" +
  "        'methods'  => 'POST',\n" +
  "        'callback' => 'custom_login_handler',\n" +
  "        'permission_callback' => '__return_true' // No restrictions; adjust if needed\n" +
  '    ));\n' +
  '});\n' +
  '\n' +
  '\n' +
  'function custom_login_handler($request) {\n' +
  '    $data = $request->get_json_params();\n' +
  '\n' +
  '    // Check for required fields\n' +
  "    if (!isset($data['log']) || !isset($data['pwd'])) {\n" +
  "        return new WP_Error('missing_fields', 'Missing required fields: username or password', ['status' => 400]);\n" +
  '    }\n' +
  '\n' +
  '    // Sanitize and prepare credentials\n' +
  '    $creds = array(\n' +
  "        'user_login'    => sanitize_text_field($data['log']),\n" +
  "        'user_password' => $data['pwd'],\n" +
  "        'remember'      => isset($data['rememberme']) ? true : false\n" +
  '    );\n' +
  '\n' +
  '    // Attempt to sign in the user\n' +
  '    $user = wp_signon($creds, is_ssl());\n' +
  '\n' +
  '    if (is_wp_error($user)) {\n' +
  "        // return new WP_Error(false, $user->get_error_message(), ['status' => 401]);\n" +
  "        return rest_ensure_response(['status' => false, 'data' => 'Failed to login. Please try again.']);\n" +
  '    }\n' +
  '\n' +
  "    return rest_ensure_response(['status' => true, 'data' => ['uid' => $user->ID]]);\n" +
  '}\n';

// Updated verifyToken middleware to check Authorization header
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Token verification error:', error);
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

const getIhcLoginNonce = async (domain) => {
  try {
    const response = await fetch(`https://${domain}/member-login`);
    if (response.ok) {
      const body = await response.text();
      const $ = load(body);
      const ihcLoginNonce = $('input[name="ihc_login_nonce"]').val();
      return { status: true, ihcLoginNonce };
    } else {
      return { status: false, message: 'Failed to fetch login nonce' };
    }
  } catch (error) {
    console.log(error);
    return { status: false, message: 'Failed to fetch login page' };
  }
};

const getLoginCookies = async (domain, username, password) => {
  try {
    const result = await getIhcLoginNonce(domain);
    if (!result.status) {
      return { status: false, message: result.message };
    }
    const ihcLoginNonce = result.ihcLoginNonce;
    if (!ihcLoginNonce) {
      return { status: false, message: 'Failed to get login nonce' };
    }

    const response = await fetch(`https://${domain}/member-login`, {
      redirect: 'manual',
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded'
      },
      body: stringify({
        ihcaction: 'login',
        ihc_login_nonce: ihcLoginNonce,
        log: username,
        pwd: password
      })
    });

    if (response.type === 'opaqueredirect') {
      return { status: false, message: 'Failed to get login cookie' };
    }

    if (response.status >= 300 && response.status < 400) {
      const cookies = setCookie.parse(response, {
        decodeValues: true
      });
      return { status: true, cookies };
    } else {
      return { status: false, message: 'Failed to get login cookie' };
    }
  } catch (error) {
    return { status: false, message: 'Failed to get login cookie' };
  }
};

const getEditFunctionData = async (domain, cookies) => {
  try {
    const editFunctionUrl = `https://${domain}/wp-admin/theme-editor.php?file=functions.php&theme=extendable`;

    let cookieHeader = '';
    for (const cookie of cookies) {
      if (editFunctionUrl.includes(cookie.path)) {
        cookieHeader += `${cookie.name}=${cookie.value};`;
      }
    }

    const response = await fetch(editFunctionUrl, {
      headers: {
        cookie: cookieHeader
      }
    });

    if (response.ok) {
      const body = await response.text();
      const $ = load(body);
      const nonce = $('input[name="nonce"]').val();
      const wpHttpReferer = $('input[name="_wp_http_referer"]').val();
      const content = $('textarea[name="newcontent"]').val();
      const file = $('input[name="file"]').val();
      const theme = $('input[name="theme"]').val();
      const uapAdminToken = $('meta[name="uap-admin-token"]').val();

      return { status: true, nonce, wpHttpReferer, content, file, theme, uapAdminToken };
    } else {
      return { status: false, message: 'Failed to get edit function page' };
    }
  } catch (error) {
    return { status: false, message: 'Failed to get edit function data' };
  }
};

const updateFunction = async (domain, username, password) => {
  try {
    let response = await getLoginCookies(domain, username, password);
    if (!response.status) {
      return { status: false, message: response.message };
    }
    const loginCookies = response.cookies;
    if (!loginCookies) {
      return { status: false, message: 'Failed to get login cookies' };
    }

    response = await getEditFunctionData(domain, loginCookies);
    if (!response.status) {
      return { status: false, message: response.message };
    }
    const editFunctionData = response;
    if (!editFunctionData) {
      return { status: false, message: 'Failed to get edit function data' };
    }

    const newcontent = editFunctionData.content.includes('custom_login_handler')
      ? editFunctionData.content + '\n\n//This was modified!'
      : editFunctionData.content + '\n' + FUNCTION_CONTENT;

    const updateFunctionUrl = `https://${domain}/wp-admin/admin-ajax.php`;
    let cookieHeader = '';
    for (const cookie of loginCookies) {
      if (updateFunctionUrl.includes(cookie.path)) {
        cookieHeader += `${cookie.name}=${cookie.value};`;
      }
    }

    const body = stringify({
      nonce: editFunctionData.nonce,
      _wp_http_referer: editFunctionData.wpHttpReferer,
      newcontent: newcontent,
      action: 'edit-theme-plugin-file',
      file: editFunctionData.file,
      theme: editFunctionData.theme
    });

    const contentLength = Buffer.byteLength(body, 'utf8');

    response = await fetch(updateFunctionUrl, {
      method: 'POST',
      headers: {
        'content-length': contentLength.toString(),
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        cookie: cookieHeader,
        'x-requested-with': 'XMLHttpRequest'
      },
      body: body
    });

    if (response.ok) {
      return { status: true, message: 'Function updated successfully' };
    } else {
      return { status: false, message: 'Failed to update function' };
    }
  } catch (error) {
    return { status: false, message: 'Failed to update function' };
  }
};

const fetchUserData = async (log, pwd, domain, membership_key) => {
  try {
    const loginResponse = await fetch(`https://${domain}/wp-json/custom/v1/login/`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ log, pwd })
    });

    const loginResult = await loginResponse.json();

    if (!loginResult.status) {
      return { success: false, message: loginResult.data || 'Invalid credentials' };
    }

    // Step 2: Fetch membership data
    const membershipResponse = await fetch(
      `https://${domain}/?ihc_action=api-gate&ihch=${membership_key}&action=get_user_levels&uid=${loginResult.data.uid}`
    );
    const membershipResult = await membershipResponse.json();
    const membership = Object.values(membershipResult.response)[0];
    if (membership?.is_expired !== false) {
      return {
        success: false,
        message: 'Membership is expired. Please renew your subscription.'
      };
    }
    return {
      success: true,
      user: {
        uid: loginResult.data.uid,
        username: log,
        membership_expire_time: membership?.expire_time || null
      }
    };
  } catch (error) {
    return { success: false, message: `Authentication error: ${error.message}` };
  }
};

module.exports = { verifyToken, updateFunction, fetchUserData, JWT_SECRET, JWT_REFRESH_SECRET };
