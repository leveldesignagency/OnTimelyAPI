// Minimal endpoint to update an existing Supabase Auth user's password by email
// Does NOT attempt to create users. Returns 404 if user is not found.

const { createClient } = require('@supabase/supabase-js');

function setCors(res, origin) {
  res.setHeader('Access-Control-Allow-Origin', origin || '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Max-Age', '86400');
}

module.exports = async function handler(req, res) {
  try {
    const origin = req.headers.origin;
    const allowedOrigins = [
      'https://dashboard.ontimely.co.uk',
      'https://on-timely-web.vercel.app',
      'http://localhost:5173',
      'http://localhost:3000'
    ];
    const corsOrigin = allowedOrigins.includes(origin) ? origin : '*';
    setCors(res, corsOrigin);
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      return res.status(204).end();
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;

    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ error: 'Missing Supabase environment variables' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    const { email, password } = req.body || {};

    const normalizedEmail = String(email || '').trim().toLowerCase();
    if (!normalizedEmail || !password) {
      return res.status(400).json({ error: 'Missing email or password' });
    }

    // Query GoTrue admin API directly by email (no DB/pagination dependency)
    let foundUser = null;
    const url = `${SUPABASE_URL}/auth/v1/admin/users?email=${encodeURIComponent(normalizedEmail)}`;
    const r = await fetch(url, {
      method: 'GET',
      headers: {
        'apikey': SUPABASE_SERVICE_ROLE_KEY,
        'Authorization': `Bearer ${SUPABASE_SERVICE_ROLE_KEY}`,
        'Content-Type': 'application/json'
      }
    });

    if (!r.ok) {
      const text = await r.text().catch(() => '');
      return res.status(500).json({ error: 'gotrue_query_failed', details: text || r.statusText });
    }

    const users = await r.json();
    if (Array.isArray(users) && users.length > 0) {
      foundUser = users.find(u => (u.email || '').toLowerCase() === normalizedEmail) || users[0];
    }

    if (!foundUser) {
      return res.status(404).json({ error: 'user_not_found' });
    }

    const { error: updErr } = await supabase.auth.admin.updateUserById(foundUser.id, { password });
    if (updErr) {
      return res.status(500).json({ error: updErr.message });
    }

    return res.status(200).json({ auth_user_id: foundUser.id });
  } catch (e) {
    return res.status(500).json({ error: 'Internal server error' });
  }
}


