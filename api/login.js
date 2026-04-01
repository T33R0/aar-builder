const crypto = require('crypto');

// Hardcoded users — no outbound HTTP calls needed for auth.
// Password changes update Supabase; this table is the boot source.
const USERS = {
  'rteehan': {
    id: '8b5f4f9a-b2fd-4c4d-8e81-9b18866f5fb0',
    displayName: 'Rory Teehan',
    orgId: '4eae9d01-bb45-451f-b51d-79d33765fc97',
    orgName: 'UCHealth Emergency Management - Northern Region',
    hash: '59854c7755d00d08763d6d9cee9e907a56e08c341d1d27e1cf7d6ebf6e3df172',
  },
  'jeisenbach': {
    id: '909ba594-8416-4f62-8d18-d92985311314',
    displayName: 'Jason Eisenbach',
    orgId: '4eae9d01-bb45-451f-b51d-79d33765fc97',
    orgName: 'UCHealth Emergency Management - Northern Region',
    hash: '59854c7755d00d08763d6d9cee9e907a56e08c341d1d27e1cf7d6ebf6e3df172',
  },
  'kschuster': {
    id: 'b7739f35-1aa5-4d0a-9b5f-3c0adefb184e',
    displayName: 'Katey Schuster',
    orgId: '4eae9d01-bb45-451f-b51d-79d33765fc97',
    orgName: 'UCHealth Emergency Management - Northern Region',
    hash: '59854c7755d00d08763d6d9cee9e907a56e08c341d1d27e1cf7d6ebf6e3df172',
  },
};

function hashPassword(pw) {
  return crypto.createHash('sha256').update('aar-salt:' + pw).digest('hex');
}

function createToken(userId) {
  var secret = process.env.AAR_TOKEN_SECRET || 'fallback-dev-secret';
  var expiry = Date.now() + 30 * 24 * 60 * 60 * 1000;
  var payload = userId + ':' + expiry;
  var hmac = crypto.createHmac('sha256', secret).update(payload).digest('hex');
  return Buffer.from(payload + ':' + hmac).toString('base64');
}

module.exports = function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  var body = req.body;
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch (e) { body = {}; }
  }

  var username = ((body && body.username) || '').trim().toLowerCase();
  var password = ((body && body.password) || '').trim();

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  var user = USERS[username];
  if (!user) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  var hash = hashPassword(password);
  if (hash !== user.hash) {
    return res.status(401).json({ success: false, error: 'Invalid credentials' });
  }

  var token = createToken(user.id);

  return res.status(200).json({
    success: true,
    user: {
      id: user.id,
      username: username,
      displayName: user.displayName,
      orgId: user.orgId,
      orgName: user.orgName,
    },
    branding: {},
    token: token,
  });
};
