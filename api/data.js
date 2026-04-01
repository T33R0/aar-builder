var crypto = require('crypto');
var https = require('https');
var urlMod = require('url');

function validateToken(token) {
  try {
    var decoded = Buffer.from(token, 'base64').toString();
    var parts = decoded.split(':');
    if (parts.length !== 3) return null;
    var userId = parts[0], expiry = parts[1], hmac = parts[2];
    if (Date.now() > parseInt(expiry)) return null;
    var secret = process.env.AAR_TOKEN_SECRET || 'fallback-dev-secret';
    var expected = crypto.createHmac('sha256', secret)
      .update(userId + ':' + expiry).digest('hex');
    if (hmac !== expected) return null;
    return userId;
  } catch (e) { return null; }
}

function sb(path, opts) {
  opts = opts || {};
  var fullUrl = (process.env.SUPABASE_URL || '') + '/rest/v1/' + path;
  var parsed = urlMod.parse(fullUrl);
  var method = opts.method || 'GET';
  var bodyStr = opts.body ? JSON.stringify(opts.body) : null;
  var headers = {
    'apikey': process.env.SUPABASE_SERVICE_ROLE_KEY || '',
    'Authorization': 'Bearer ' + (process.env.SUPABASE_SERVICE_ROLE_KEY || ''),
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
  if (opts.prefer) headers['Prefer'] = opts.prefer;
  if (bodyStr) headers['Content-Length'] = Buffer.byteLength(bodyStr);

  return new Promise(function (resolve, reject) {
    var req = https.request({
      hostname: parsed.hostname,
      port: parsed.port || 443,
      path: parsed.path,
      method: method,
      headers: headers,
    }, function (res) {
      var chunks = [];
      res.on('data', function (c) { chunks.push(c); });
      res.on('end', function () {
        var text = Buffer.concat(chunks).toString();
        if (method === 'DELETE' && !text) { resolve({ ok: true }); return; }
        try { resolve(JSON.parse(text)); } catch (e) { resolve(text); }
      });
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

function getUser(userId) {
  return sb('aar_users?id=eq.' + userId + '&select=id,username,display_name,org_id').then(function (users) {
    return (Array.isArray(users) && users.length) ? users[0] : null;
  });
}

module.exports = async function handler(req, res) {
  var auth = (req.headers.authorization || '').replace('Bearer ', '');
  var userId = validateToken(auth);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    return res.status(500).json({ error: 'Server misconfigured: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY not set' });
  }

  var user;
  try {
    user = await getUser(userId);
  } catch (err) {
    return res.status(500).json({ error: 'DB connection failed: ' + err.message });
  }
  if (!user) return res.status(401).json({ error: 'User not found' });

  var action = req.query.action;
  var body = req.body;
  if (typeof body === 'string') try { body = JSON.parse(body); } catch (e) { body = {}; }
  if (req.method === 'POST' && body && body.action) action = body.action;

  try {

  if (req.method === 'GET' && action === 'documents') {
    var docs = await sb(
      'aar_documents?org_id=eq.' + user.org_id +
      '&select=id,owner_id,owner_username,meta,created_at,updated_at&order=updated_at.desc'
    );
    return res.json({ documents: Array.isArray(docs) ? docs : [] });
  }

  if (req.method === 'GET' && action === 'document') {
    var docId = req.query.id;
    if (!docId) return res.status(400).json({ error: 'Missing id' });
    var docs = await sb('aar_documents?id=eq.' + encodeURIComponent(docId) + '&org_id=eq.' + user.org_id);
    if (!Array.isArray(docs) || !docs.length) return res.status(404).json({ error: 'Not found' });
    return res.json({ document: docs[0] });
  }

  if (req.method === 'POST' && action === 'save-document') {
    var doc = body.document;
    if (!doc || !doc.id) return res.status(400).json({ error: 'Missing document' });
    var existing = await sb('aar_documents?id=eq.' + encodeURIComponent(doc.id) + '&select=id,owner_id');
    if (Array.isArray(existing) && existing.length) {
      await sb('aar_documents?id=eq.' + encodeURIComponent(doc.id), {
        method: 'PATCH',
        body: { meta: doc.meta, state: doc.state, updated_at: new Date().toISOString() },
        prefer: 'return=minimal',
      });
    } else {
      await sb('aar_documents', {
        method: 'POST',
        body: {
          id: doc.id,
          org_id: user.org_id,
          owner_id: user.id,
          owner_username: user.username,
          meta: doc.meta,
          state: doc.state,
        },
        prefer: 'return=minimal',
      });
    }
    return res.json({ success: true });
  }

  if (req.method === 'POST' && action === 'delete-document') {
    var docId = body.id;
    if (!docId) return res.status(400).json({ error: 'Missing id' });
    var docs = await sb('aar_documents?id=eq.' + encodeURIComponent(docId) + '&select=owner_id');
    if (!Array.isArray(docs) || !docs.length) return res.status(404).json({ error: 'Not found' });
    if (docs[0].owner_id !== user.id) return res.status(403).json({ error: 'Only the owner can delete' });
    await sb('aar_documents?id=eq.' + encodeURIComponent(docId), { method: 'DELETE' });
    return res.json({ success: true });
  }

  if (req.method === 'GET' && action === 'branding') {
    var orgs = await sb('aar_organizations?id=eq.' + user.org_id + '&select=branding');
    return res.json({ branding: (Array.isArray(orgs) && orgs[0]) ? orgs[0].branding : {} });
  }

  if (req.method === 'POST' && action === 'save-branding') {
    if (!body.branding) return res.status(400).json({ error: 'Missing branding' });
    await sb('aar_organizations?id=eq.' + user.org_id, {
      method: 'PATCH',
      body: { branding: body.branding, updated_at: new Date().toISOString() },
      prefer: 'return=minimal',
    });
    return res.json({ success: true });
  }

  if (req.method === 'GET' && action === 'organizations') {
    var orgs = await sb('aar_organizations?select=id,name&order=name');
    return res.json({ organizations: Array.isArray(orgs) ? orgs : [] });
  }

  if (req.method === 'POST' && action === 'change-org') {
    var orgId = body.orgId;
    if (!orgId) return res.status(400).json({ error: 'Missing orgId' });
    await sb('aar_users?id=eq.' + user.id, {
      method: 'PATCH',
      body: { org_id: orgId },
      prefer: 'return=minimal',
    });
    var orgs = await sb('aar_organizations?id=eq.' + orgId + '&select=id,name,branding');
    var org = (Array.isArray(orgs) && orgs[0]) || null;
    return res.json({ success: true, org: org });
  }

  if (req.method === 'POST' && action === 'change-password') {
    var np = (body.newPassword || '').trim();
    if (!np) return res.status(400).json({ error: 'Missing password' });
    var hash = crypto.createHash('sha256').update('aar-salt:' + np).digest('hex');
    await sb('aar_users?id=eq.' + user.id, {
      method: 'PATCH',
      body: { password_hash: hash },
      prefer: 'return=minimal',
    });
    return res.json({ success: true });
  }

  if (req.method === 'POST' && action === 'import-documents') {
    var docs = body.documents;
    if (!docs || !Array.isArray(docs)) return res.status(400).json({ error: 'Missing documents array' });
    for (var i = 0; i < docs.length; i++) {
      var d = docs[i];
      var exists = await sb('aar_documents?id=eq.' + encodeURIComponent(d.id) + '&select=id');
      if (Array.isArray(exists) && exists.length) continue;
      await sb('aar_documents', {
        method: 'POST',
        body: {
          id: d.id,
          org_id: user.org_id,
          owner_id: user.id,
          owner_username: user.username,
          meta: d.meta,
          state: d.state,
        },
        prefer: 'return=minimal',
      });
    }
    return res.json({ success: true, count: docs.length });
  }

  return res.status(400).json({ error: 'Unknown action: ' + action });

  } catch (err) {
    return res.status(500).json({ error: 'Server error: ' + err.message });
  }
};
