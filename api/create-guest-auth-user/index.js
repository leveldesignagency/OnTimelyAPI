const { createClient } = require('@supabase/supabase-js');

module.exports = async function handler(req, res) {
  // Basic CORS (allow Electron/desktop app with null origin)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-internal-token');
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // Accept POST (preferred) and GET (debug fallback)
  if (req.method !== 'POST' && req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const SUPABASE_URL = process.env.SUPABASE_URL;
    const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;
    if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) {
      return res.status(500).json({ error: 'Server missing Supabase credentials' });
    }

    const payload = req.method === 'GET' ? (req.query || {}) : (req.body || {});
    const { email, password, event_id, guest_id, first_name, last_name, company_id } = payload;
    if (!email || !password || !event_id || !guest_id) {
      return res.status(400).json({ error: 'Missing fields: email, password, event_id, guest_id' });
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);

    // Try to create the user first
    const { data: createData, error: createError } = await supabase.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        provider: 'guest',
        role: 'guest',
        guest_id,
        event_id,
        first_name,
        last_name,
        company_id,
        email_verified: true
      },
      app_metadata: { provider: 'email', providers: ['email', 'guest'] }
    });

    let authUserId = createData?.user?.id || null;

    if (createError && !String(createError.message || '').includes('already registered')) {
      return res.status(500).json({ error: createError.message });
    }

    // If the user already exists, locate and update password/metadata
    if (!authUserId) {
      const { data: list, error: listErr } = await supabase.auth.admin.listUsers({ page: 1, perPage: 200 });
      if (listErr) return res.status(500).json({ error: listErr.message });
      const existing = list.users.find(u => (u.email || '').toLowerCase() === String(email).toLowerCase());
      if (!existing) return res.status(500).json({ error: 'User exists but could not be fetched' });
      const { error: updErr } = await supabase.auth.admin.updateUserById(existing.id, {
        password,
        user_metadata: {
          provider: 'guest',
          role: 'guest',
          guest_id,
          event_id,
          first_name,
          last_name,
          company_id,
          email_verified: true
        },
        app_metadata: { provider: 'email', providers: ['email', 'guest'] }
      });
      if (updErr) return res.status(500).json({ error: updErr.message });
      authUserId = existing.id;
    }

    return res.status(200).json({ auth_user_id: authUserId });
  } catch (e) {
    console.error('[create-guest-auth-user] error:', e);
    return res.status(500).json({ error: 'Internal server error' });
  }
};