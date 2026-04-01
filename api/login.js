const crypto = require('crypto');
const https = require('https');

function hashPassword(pw) {
  return crypto.createHash('sha256').update('aar-salt:' + pw).digest('hex');
}

function createToken(userId) {
  const expiry = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30 days
  const payload = userId + ':' + expiry;
  const hmac = crypto.createHmac('sha256', process.env.AAR_TOKEN_SECRET).update(payload).digest('hex');
  return Buffer.from(payload + ':' + hmac).toString('base64');
}

function sbGet(path) {
  return new Promise(function (resolve, reject) {
    var parsed = new URL(process.env.SUPABASE_URL + '/rest/v1/' + path);
    var opts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      headers: {
        'apikey': process.env.SUPABASE_SERVICE_KEY,
        'Authorization': 'Bearer ' + process.env.SUPABASE_SERVICE_KEY,
        'Accept': 'application/json',
      },
    };
    var req = https.request(opts, function (res) {
      var body = '';
      res.on('data', function (c) { body += c; });
      res.on('end', function () {
        try { resolve(JSON.parse(body)); } catch (e) { resolve(body); }
      });
    });
    req.on('error', reject);
    req.end();
  });
}

module.exports = async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  let body = req.body;
  if (typeof body === 'string') try { body = JSON.parse(body); } catch (e) { body = {}; }

  const username = ((body && body.username) || '').trim().toLowerCase();
  const password = ((body && body.password) || '').trim();
  if (!username || !password) return res.status(400).json({ error: 'Username and password required' });

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_KEY || !process.env.AAR_TOKEN_SECRET) {
    return res.status(500).json({ error: 'Server misconfigured: missing env vars' });
  }

  try {
    const hash = hashPassword(password);

    const users = await sbGet(
      'aar_users?username=eq.' + encodeURIComponent(username) +
      '&password_hash=eq.' + hash +
      '&select=id,username,display_name,org_id'
    );

    if (!Array.isArray(users) || users.length === 0) {
      return res.status(401).json({ success: false, error: 'Invalid credentials' });
    }

    const user = users[0];

    let org = null;
    if (user.org_id) {
      const orgs = await sbGet('aar_organizations?id=eq.' + user.org_id + '&select=id,name,branding');
      if (Array.isArray(orgs) && orgs.length) org = orgs[0];
    }

    const token = createToken(user.id);

    return res.status(200).json({
      success: true,
      user: {
        id: user.id,
        username: user.username,
        displayName: user.display_name,
        orgId: user.org_id,
        orgName: org ? org.name : null,
      },
      branding: org ? org.branding : {},
      token: token,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Server error: ' + err.message });
  }
};
