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

    // Find existing user by iterating listUsers (no direct getUserByEmail in admin API)
    let foundUser = null;
    let page = 1;
    const perPage = 1000;
    while (!foundUser && page <= 10) {
      const { data: list, error: listErr } = await supabase.auth.admin.listUsers({ page, perPage });
      if (listErr) {
        return res.status(500).json({ error: listErr.message });
      }
      foundUser = (list.users || []).find(u => (u.email || '').toLowerCase() === normalizedEmail);
      if (foundUser || (list.users || []).length < perPage) break;
      page += 1;
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


