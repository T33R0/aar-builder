const crypto = require('crypto');
const https = require('https');

function validateToken(token) {
  try {
    var decoded = Buffer.from(token, 'base64').toString();
    var parts = decoded.split(':');
    if (parts.length !== 3) return null;
    var userId = parts[0], expiry = parts[1], hmac = parts[2];
    if (Date.now() > parseInt(expiry)) return null;
    var expected = crypto.createHmac('sha256', process.env.AAR_TOKEN_SECRET)
      .update(userId + ':' + expiry).digest('hex');
    if (hmac !== expected) return null;
    return userId;
  } catch (e) { return null; }
}

function sbRequest(path, opts) {
  opts = opts || {};
  return new Promise(function (resolve, reject) {
    var parsed = new URL(process.env.SUPABASE_URL + '/rest/v1/' + path);
    var headers = {
      'apikey': process.env.SUPABASE_SERVICE_KEY,
      'Authorization': 'Bearer ' + process.env.SUPABASE_SERVICE_KEY,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    };
    if (opts.prefer) headers['Prefer'] = opts.prefer;
    var reqOpts = {
      hostname: parsed.hostname,
      path: parsed.pathname + parsed.search,
      method: opts.method || 'GET',
      headers: headers,
    };
    var req = https.request(reqOpts, function (res) {
      var body = '';
      res.on('data', function (c) { body += c; });
      res.on('end', function () {
        if (opts.method === 'DELETE' && !body) { resolve({ ok: true }); return; }
        try { resolve(JSON.parse(body)); } catch (e) { resolve(body); }
      });
    });
    req.on('error', reject);
    if (opts.body) req.write(JSON.stringify(opts.body));
    req.end();
  });
}

function sb(path, opts) { return sbRequest(path, opts); }

async function getUser(userId) {
  var users = await sb('aar_users?id=eq.' + userId + '&select=id,username,display_name,org_id');
  return (Array.isArray(users) && users.length) ? users[0] : null;
}

module.exports = async function handler(req, res) {
  var auth = (req.headers.authorization || '').replace('Bearer ', '');
  var userId = validateToken(auth);
  if (!userId) return res.status(401).json({ error: 'Unauthorized' });

  var user = await getUser(userId);
  if (!user) return res.status(401).json({ error: 'User not found' });

  var action = req.query.action;
  var body = req.body;
  if (typeof body === 'string') try { body = JSON.parse(body); } catch (e) { body = {}; }
  if (req.method === 'POST' && body && body.action) action = body.action;

  try {

  // === LIST DOCUMENTS (org-scoped) ===
  if (req.method === 'GET' && action === 'documents') {
    var docs = await sb(
      'aar_documents?org_id=eq.' + user.org_id +
      '&select=id,owner_id,owner_username,meta,created_at,updated_at&order=updated_at.desc'
    );
    return res.json({ documents: Array.isArray(docs) ? docs : [] });
  }

  // === GET SINGLE DOCUMENT ===
  if (req.method === 'GET' && action === 'document') {
    var docId = req.query.id;
    if (!docId) return res.status(400).json({ error: 'Missing id' });
    var docs = await sb('aar_documents?id=eq.' + encodeURIComponent(docId) + '&org_id=eq.' + user.org_id);
    if (!Array.isArray(docs) || !docs.length) return res.status(404).json({ error: 'Not found' });
    return res.json({ document: docs[0] });
  }

  // === SAVE DOCUMENT (upsert) ===
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

  // === DELETE DOCUMENT (owner only) ===
  if (req.method === 'POST' && action === 'delete-document') {
    var docId = body.id;
    if (!docId) return res.status(400).json({ error: 'Missing id' });
    var docs = await sb('aar_documents?id=eq.' + encodeURIComponent(docId) + '&select=owner_id');
    if (!Array.isArray(docs) || !docs.length) return res.status(404).json({ error: 'Not found' });
    if (docs[0].owner_id !== user.id) return res.status(403).json({ error: 'Only the owner can delete' });
    await sb('aar_documents?id=eq.' + encodeURIComponent(docId), { method: 'DELETE' });
    return res.json({ success: true });
  }

  // === GET BRANDING ===
  if (req.method === 'GET' && action === 'branding') {
    var orgs = await sb('aar_organizations?id=eq.' + user.org_id + '&select=branding');
    return res.json({ branding: (Array.isArray(orgs) && orgs[0]) ? orgs[0].branding : {} });
  }

  // === SAVE BRANDING (org-level) ===
  if (req.method === 'POST' && action === 'save-branding') {
    if (!body.branding) return res.status(400).json({ error: 'Missing branding' });
    await sb('aar_organizations?id=eq.' + user.org_id, {
      method: 'PATCH',
      body: { branding: body.branding, updated_at: new Date().toISOString() },
      prefer: 'return=minimal',
    });
    return res.json({ success: true });
  }

  // === LIST ORGANIZATIONS ===
  if (req.method === 'GET' && action === 'organizations') {
    var orgs = await sb('aar_organizations?select=id,name&order=name');
    return res.json({ organizations: Array.isArray(orgs) ? orgs : [] });
  }

  // === CHANGE ORGANIZATION ===
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

  // === CHANGE PASSWORD ===
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

  // === IMPORT DOCUMENTS (bulk, for localStorage migration) ===
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
