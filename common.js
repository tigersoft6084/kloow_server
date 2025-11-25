const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const JWT_SECRET = 'proxyservicejwttoken';
const JWT_REFRESH_SECRET = 'proxyservicejwtrefreshtoken';

const FUNCTION_TO_INJECT = `
add_action('rest_api_init', function () {
    register_rest_route('custom/v1', '/login/', array(
        'methods'  => 'POST',
        'callback' => 'custom_login_handler',
        'permission_callback' => '__return_true' // No restrictions; adjust if needed
    ));
});


function custom_login_handler($request) {
    $data = $request->get_json_params();

    // Check for required fields
    if (!isset($data['log']) || !isset($data['pwd'])) {
        return new WP_Error('missing_fields', 'Missing required fields: username or password', ['status' => 400]);
    }

    // Sanitize and prepare credentials
    $creds = array(
        'user_login'    => sanitize_text_field($data['log']),
        'user_password' => $data['pwd'],
        'remember'      => isset($data['rememberme']) ? true : false
    );

    // Attempt to sign in the user
    $user = wp_signon($creds, is_ssl());

    if (is_wp_error($user)) {
        // return new WP_Error(false, $user->get_error_message(), ['status' => 401]);
        return rest_ensure_response(['status' => false, 'data' => 'Failed to login. Please try again.']);
    }

    return rest_ensure_response(['status' => true, 'data' => ['uid' => $user->ID, 'roles' => $user->roles]]);
}
`;

// Updated verifyToken middleware to check Authorization header
const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    console.warn(`[verifyToken] no auth header for ${req.method} ${req.originalUrl}`);
    return res.status(401).json({ message: 'No token provided' });
  }

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    return next();
  } catch (error) {
    console.error('[verifyToken] Token verification error:', error);
    return res.status(401).json({ message: 'Invalid or expired token' });
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

    const membershipResponse = await fetch(
      `https://${domain}/?ihc_action=api-gate&ihch=${membership_key}&action=get_user_levels&uid=${loginResult.data.uid}`
    );

    const membershipResult = await membershipResponse.json();
    const membershipList = Object.values(membershipResult.response);
    // get membership details for the first membership in the list

    const fetchPromises = membershipList
      .filter((item) => item.is_expired === false)
      .map(async (item) => {
        const levelId = item.level_id;
        const url = `https://${domain}/?ihc_action=api-gate&ihch=${membership_key}&action=get_level_details&lid=${levelId}`;

        try {
          const response = await fetch(url);
          if (!response.ok) {
            throw new Error(`HTTP ${response.status} - Failed to fetch level ${levelId}`);
          }
          const data = await response.json();
          return {
            level_id: levelId,
            label: item.label || '-',
            expire_time: item.expire_time || '2000-12-31 23:59:59',
            price: data.response.price || 0
          };
        } catch (error) {
          console.error(`Error fetching membership level ${levelId}:`, error);
          return null;
        }
      });
    const membershipDetails = await Promise.all(fetchPromises);

    let membership = null;

    // get the membership with the highest price
    for (const detail of membershipDetails) {
      if (detail && (!membership || parseFloat(detail.price) > parseFloat(membership.price))) {
        membership = detail;
      }
    }

    return {
      success: true,
      user: {
        uid: loginResult.data.uid,
        role: loginResult.data.roles.includes('administrator') ? 'admin' : 'user',
        username: log,
        membership_id: membership?.level_id || 0,
        membership_name: membership?.label || '-',
        membership_expire_time: loginResult.data.roles.includes('administrator')
          ? '2100-12-31 23:59:59'
          : membership?.expire_time || '2000-12-31 23:59:59'
      }
    };
  } catch (error) {
    return { success: false, message: `Authentication error: ${error.message}` };
  }
};

const hashId = (id) => {
  return crypto.createHash('md5').update(id).digest('hex');
};

module.exports = { verifyToken, fetchUserData, hashId, JWT_SECRET, JWT_REFRESH_SECRET, FUNCTION_TO_INJECT };
