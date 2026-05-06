 // ============================================
// AirDrop Zone — Cloudflare Worker API
// Database: Cloudflare D1 (5GB free)
// Auth: Email/Password + Web3 Wallet
// ============================================

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Simple JWT-like token using Web Crypto
async function makeToken(userId, env) {
  const data = JSON.stringify({ id: userId, ts: Date.now() });
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigB64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return btoa(data) + '.' + sigB64;
}

async function verifyToken(token, env) {
  try {
    const [dataB64, sigB64] = token.split('.');
    const data = atob(dataB64);
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(env.JWT_SECRET), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
    const sig = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const valid = await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(data));
    if (!valid) return null;
    const parsed = JSON.parse(data);
    // Token valid for 30 days
    if (Date.now() - parsed.ts > 30 * 24 * 60 * 60 * 1000) return null;
    return parsed;
  } catch { return null; }
}

async function hashPassword(password) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password + 'ADZ_SALT_2025'));
  return btoa(String.fromCharCode(...new Uint8Array(buf)));
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), { status, headers: { ...CORS, 'Content-Type': 'application/json' } });
}

function err(msg, status = 400) {
  return json({ error: msg }, status);
}

async function getUser(req, env) {
  const auth = req.headers.get('Authorization') || '';
  const token = auth.replace('Bearer ', '');
  if (!token) return null;
  const parsed = await verifyToken(token, env);
  if (!parsed) return null;
  const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(parsed.id).first();
  return user;
}

export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { headers: CORS });

    const url = new URL(req.url);
    const path = url.pathname;

    // ── AUTH ROUTES ──────────────────────────────
    if (path === '/api/auth/register' && req.method === 'POST') {
      const { username, email, password, ref_code } = await req.json();
      if (!username || !email || !password) return err('All fields required');
      if (password.length < 6) return err('Password min 6 chars');

      const exists = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first();
      if (exists) return err('Email already registered');

      const uExists = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username.toLowerCase()).first();
      if (uExists) return err('Username taken');

      const hashed = await hashPassword(password);
      const myRef = 'ADZ' + Math.random().toString(36).substr(2, 7).toUpperCase();
      const id = crypto.randomUUID();
      const cfg = await env.DB.prepare("SELECT value FROM settings WHERE key = 'welcome_bonus'").first();
      const bonus = parseInt(cfg?.value || '1000');

      await env.DB.prepare(`INSERT INTO users (id, username, email, password_hash, referral_code, referred_by, points, total_mined, mining_power, login_method, mining_claimed, created_at) VALUES (?,?,?,?,?,?,?,0,1.0,'email',1,datetime('now'))`)
        .bind(id, username.toLowerCase(), email, hashed, myRef, ref_code || null, bonus).run();

      // Welcome bonus tx
      await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
        .bind(crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus').run();

      // Process referral
      if (ref_code) {
        const refUser = await env.DB.prepare('SELECT * FROM users WHERE referral_code = ?').bind(ref_code).first();
        if (refUser && refUser.id !== id) {
          const cfgR = await env.DB.prepare("SELECT value FROM settings WHERE key = 'referral_bonus'").first();
          const rb = parseInt(cfgR?.value || '500');
          await env.DB.prepare('UPDATE users SET points = points + ?, referral_count = referral_count + 1 WHERE id = ?').bind(rb, refUser.id).run();
          await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
            .bind(crypto.randomUUID(), refUser.id, 'referral_bonus', rb, '👥 New referral: @' + username).run();
        }
      }

      const token = await makeToken(id, env);
      const user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      return json({ token, user });
    }

    if (path === '/api/auth/login' && req.method === 'POST') {
      const { email, password } = await req.json();
      if (!email || !password) return err('Email and password required');
      const hashed = await hashPassword(password);
      const user = await env.DB.prepare('SELECT * FROM users WHERE email = ? AND password_hash = ?').bind(email, hashed).first();
      if (!user) return err('Wrong email or password');
      if (user.is_banned) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    if (path === '/api/auth/wallet' && req.method === 'POST') {
      const { wallet_address, wallet_type, ref_code } = await req.json();
      if (!wallet_address) return err('Wallet address required');

      const addr = wallet_address.toLowerCase();
      let user = await env.DB.prepare('SELECT * FROM users WHERE wallet_address = ?').bind(addr).first();

      if (!user) {
        // New wallet user
        const id = crypto.randomUUID();
        const shortName = wallet_address.slice(0, 6) + '...' + wallet_address.slice(-4);
        const username = 'w_' + wallet_address.slice(2, 10).toLowerCase();
        const myRef = 'ADZ' + Math.random().toString(36).substr(2, 7).toUpperCase();
        const cfg = await env.DB.prepare("SELECT value FROM settings WHERE key = 'welcome_bonus'").first();
        const bonus = parseInt(cfg?.value || '1000');

        await env.DB.prepare(`INSERT INTO users (id, username, wallet_address, wallet_type, referral_code, referred_by, points, total_mined, mining_power, login_method, mining_claimed, created_at) VALUES (?,?,?,?,?,?,?,0,1.0,?,1,datetime('now'))`)
          .bind(id, username, addr, wallet_type || 'web3', myRef, ref_code || null, bonus, wallet_type || 'wallet').run();

        await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
          .bind(crypto.randomUUID(), id, 'welcome_bonus', bonus, '🎉 Welcome bonus').run();

        if (ref_code) {
          const refUser = await env.DB.prepare('SELECT * FROM users WHERE referral_code = ?').bind(ref_code).first();
          if (refUser) {
            const cfgR = await env.DB.prepare("SELECT value FROM settings WHERE key = 'referral_bonus'").first();
            const rb = parseInt(cfgR?.value || '500');
            await env.DB.prepare('UPDATE users SET points = points + ?, referral_count = referral_count + 1 WHERE id = ?').bind(rb, refUser.id).run();
          }
        }

        user = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(id).first();
      }

      if (user.is_banned) return err('Account banned');
      const token = await makeToken(user.id, env);
      return json({ token, user });
    }

    // ── USER ROUTES ──────────────────────────────
    if (path === '/api/me' && req.method === 'GET') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      // Recalc mining power
      const { results: refs } = await env.DB.prepare('SELECT COUNT(*) as c FROM users WHERE referred_by = ? AND total_mined > 0').bind(user.referral_code).all();
      const activeRefs = refs[0]?.c || 0;
      const cfgPPR = await env.DB.prepare("SELECT value FROM settings WHERE key = 'referral_power_per_ref'").first();
      const cfgMax = await env.DB.prepare("SELECT value FROM settings WHERE key = 'max_mining_power'").first();
      const ppr = parseFloat(cfgPPR?.value || '0.1');
      const maxP = parseFloat(cfgMax?.value || '10.0');
      const newPow = Math.min(1.0 + activeRefs * ppr, maxP);
      await env.DB.prepare('UPDATE users SET mining_power = ?, active_referral_count = ? WHERE id = ?').bind(newPow, activeRefs, user.id).run();
      const updated = await env.DB.prepare('SELECT * FROM users WHERE id = ?').bind(user.id).first();
      return json(updated);
    }

    if (path === '/api/mine/start' && req.method === 'POST') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      if (!user.mining_claimed) return err('Already mining');
      const now = new Date().toISOString();
      await env.DB.prepare("UPDATE users SET last_mining_start = ?, mining_claimed = 0 WHERE id = ?").bind(now, user.id).run();
      await env.DB.prepare("INSERT INTO mining_sessions (id, user_id, started_at, mining_power) VALUES (?,?,?,?)")
        .bind(crypto.randomUUID(), user.id, now, user.mining_power).run();
      return json({ success: true });
    }

    if (path === '/api/mine/claim' && req.method === 'POST') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      if (user.mining_claimed) return err('Nothing to claim');

      const cfg = await env.DB.prepare("SELECT key, value FROM settings WHERE key IN ('mining_duration_hours','mining_coins_per_hour')").all();
      const cfgMap = {};
      cfg.results.forEach(r => cfgMap[r.key] = r.value);
      const durMs = parseInt(cfgMap.mining_duration_hours || '24') * 3600000;
      const cpm = parseFloat(cfgMap.mining_coins_per_hour || '10') * user.mining_power / 3600000;
      const start = new Date(user.last_mining_start).getTime();
      const elapsed = Math.min(Date.now() - start, durMs);
      const earned = Math.floor(cpm * elapsed);

      if (earned < 100) return err('Mine at least 100 points first');

      const newPts = (user.points || 0) + earned;
      const newMined = (user.total_mined || 0) + earned;
      await env.DB.prepare('UPDATE users SET points = ?, total_mined = ?, total_claimed = total_claimed + ?, mining_claimed = 1 WHERE id = ?')
        .bind(newPts, newMined, earned, user.id).run();
      await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
        .bind(crypto.randomUUID(), user.id, 'mining_claim', earned, '⛏️ Mining claim').run();
      await env.DB.prepare('UPDATE mining_sessions SET claimed_at = datetime(\'now\'), coins_earned = ?, is_claimed = 1 WHERE user_id = ? AND is_claimed = 0')
        .bind(earned, user.id).run();

      // Activate referral bonus for referrer if first claim
      if (user.referred_by && newMined === earned) {
        const refUser = await env.DB.prepare('SELECT * FROM users WHERE referral_code = ?').bind(user.referred_by).first();
        if (refUser) {
          const cfgPPR = await env.DB.prepare("SELECT value FROM settings WHERE key = 'referral_power_per_ref'").first();
          const cfgMaxP = await env.DB.prepare("SELECT value FROM settings WHERE key = 'max_mining_power'").first();
          const cfgARB = await env.DB.prepare("SELECT value FROM settings WHERE key = 'active_referral_bonus'").first();
          const ppr = parseFloat(cfgPPR?.value || '0.1'), maxP = parseFloat(cfgMaxP?.value || '10.0');
          const newAR = (refUser.active_referral_count || 0) + 1;
          const newPow = Math.min(1.0 + newAR * ppr, maxP);
          const arb = parseInt(cfgARB?.value || '200');
          await env.DB.prepare('UPDATE users SET active_referral_count = ?, mining_power = ?, points = points + ? WHERE id = ?')
            .bind(newAR, newPow, arb, refUser.id).run();
          await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
            .bind(crypto.randomUUID(), refUser.id, 'active_referral_bonus', arb, '🔥 @' + user.username + ' started mining!').run();
        }
      }

      return json({ success: true, earned });
    }

    if (path === '/api/tasks' && req.method === 'GET') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      const { results: tasks } = await env.DB.prepare('SELECT * FROM tasks WHERE is_active = 1 ORDER BY display_order').all();
      const { results: done } = await env.DB.prepare('SELECT task_id FROM user_tasks WHERE user_id = ?').bind(user.id).all();
      const doneSet = new Set(done.map(d => d.task_id));
      return json({ tasks, done: [...doneSet] });
    }

    if (path === '/api/tasks/complete' && req.method === 'POST') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      const { task_id } = await req.json();
      const task = await env.DB.prepare('SELECT * FROM tasks WHERE id = ? AND is_active = 1').bind(task_id).first();
      if (!task) return err('Task not found');
      const already = await env.DB.prepare('SELECT id FROM user_tasks WHERE user_id = ? AND task_id = ?').bind(user.id, task_id).first();
      if (already) return err('Already completed');
      await env.DB.prepare("INSERT INTO user_tasks (id, user_id, task_id, completed_at) VALUES (?,?,?,datetime('now'))").bind(crypto.randomUUID(), user.id, task_id).run();
      await env.DB.prepare('UPDATE users SET points = points + ?, total_tasks_completed = total_tasks_completed + 1 WHERE id = ?').bind(task.points_reward, user.id).run();
      await env.DB.prepare("INSERT INTO transactions (id,user_id,type,amount,description,created_at) VALUES (?,?,?,?,?,datetime('now'))")
        .bind(crypto.randomUUID(), user.id, 'task_complete', task.points_reward, '✅ ' + task.title).run();
      return json({ success: true, earned: task.points_reward });
    }

    if (path === '/api/leaderboard' && req.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT username, wallet_address, wallet_type, total_mined, mining_power, active_referral_count FROM users ORDER BY total_mined DESC LIMIT 25').all();
      return json(results);
    }

    if (path === '/api/referrals' && req.method === 'GET') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      const { results } = await env.DB.prepare('SELECT username, wallet_address, total_mined, created_at FROM users WHERE referred_by = ? ORDER BY created_at DESC LIMIT 30').bind(user.referral_code).all();
      return json(results);
    }

    if (path === '/api/transactions' && req.method === 'GET') {
      const user = await getUser(req, env);
      if (!user) return err('Unauthorized', 401);
      const { results } = await env.DB.prepare('SELECT * FROM transactions WHERE user_id = ? ORDER BY created_at DESC LIMIT 30').bind(user.id).all();
      return json(results);
    }

    if (path === '/api/settings' && req.method === 'GET') {
      const { results } = await env.DB.prepare('SELECT key, value FROM settings').all();
      const map = {};
      results.forEach(r => map[r.key] = r.value);
      return json(map);
    }

    if (path === '/api/stats' && req.method === 'GET') {
      const uc = await env.DB.prepare('SELECT COUNT(*) as c FROM users').first();
      const tm = await env.DB.prepare('SELECT SUM(total_mined) as s FROM users').first();
      return json({ users: uc?.c || 0, total_mined: tm?.s || 0 });
    }

    // ── ADMIN ROUTES ──────────────────────────────
    if (path.startsWith('/api/admin/')) {
      const body = req.method !== 'GET' ? await req.json().catch(() => ({})) : {};
      const adminPass = req.headers.get('X-Admin-Key');
      if (adminPass !== env.ADMIN_KEY) return err('Forbidden', 403);

      if (path === '/api/admin/users' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM users ORDER BY created_at DESC LIMIT 100').all();
        return json(results);
      }
      if (path === '/api/admin/users/update' && req.method === 'POST') {
        const { id, username, points, mining_power, is_banned } = body;
        await env.DB.prepare('UPDATE users SET username=?,points=?,mining_power=?,is_banned=? WHERE id=?').bind(username, points, mining_power, is_banned ? 1 : 0, id).run();
        return json({ success: true });
      }
      if (path === '/api/admin/tasks' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM tasks ORDER BY display_order').all();
        return json(results);
      }
      if (path === '/api/admin/tasks/save' && req.method === 'POST') {
        const { id, title, description, icon, task_type, url, ad_url, points_reward, timer_seconds, display_order, is_active } = body;
        if (id) {
          await env.DB.prepare('UPDATE tasks SET title=?,description=?,icon=?,task_type=?,url=?,ad_url=?,points_reward=?,timer_seconds=?,display_order=?,is_active=? WHERE id=?')
            .bind(title, description||null, icon||'🎯', task_type, url||null, ad_url||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0, id).run();
        } else {
          await env.DB.prepare("INSERT INTO tasks (id,title,description,icon,task_type,url,ad_url,points_reward,timer_seconds,display_order,is_active,created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,datetime('now'))")
            .bind(crypto.randomUUID(), title, description||null, icon||'🎯', task_type, url||null, ad_url||null, points_reward, timer_seconds||0, display_order||99, is_active?1:0).run();
        }
        return json({ success: true });
      }
      if (path === '/api/admin/tasks/delete' && req.method === 'POST') {
        await env.DB.prepare('DELETE FROM tasks WHERE id=?').bind(body.id).run();
        return json({ success: true });
      }
      if (path === '/api/admin/settings' && req.method === 'POST') {
        for (const [key, value] of Object.entries(body)) {
          await env.DB.prepare('UPDATE settings SET value=? WHERE key=?').bind(String(value), key).run();
        }
        return json({ success: true });
      }
      if (path === '/api/admin/blog' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT * FROM blog_posts ORDER BY display_order').all();
        return json(results);
      }
      if (path === '/api/admin/blog/save' && req.method === 'POST') {
        const { id, title, slug, category, phase, excerpt, content, display_order, status } = body;
        const sl = slug || title.toLowerCase().replace(/[^a-z0-9]+/g,'-');
        if (id) {
          await env.DB.prepare('UPDATE blog_posts SET title=?,slug=?,category=?,phase=?,excerpt=?,content=?,display_order=?,status=? WHERE id=?')
            .bind(title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published', id).run();
        } else {
          await env.DB.prepare("INSERT INTO blog_posts (id,title,slug,category,phase,excerpt,content,display_order,status,created_at) VALUES (?,?,?,?,?,?,?,?,?,datetime('now'))")
            .bind(crypto.randomUUID(), title, sl, category||'roadmap', phase||null, excerpt||null, content||null, display_order||99, status||'published').run();
        }
        return json({ success: true });
      }
      if (path === '/api/admin/blog/delete' && req.method === 'POST') {
        await env.DB.prepare('DELETE FROM blog_posts WHERE id=?').bind(body.id).run();
        return json({ success: true });
      }
      if (path === '/api/admin/dashboard' && req.method === 'GET') {
        const [uc, tm, tc, mc, recent] = await Promise.all([
          env.DB.prepare('SELECT COUNT(*) as c FROM users').first(),
          env.DB.prepare('SELECT SUM(total_mined) as s FROM users').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM tasks WHERE is_active=1').first(),
          env.DB.prepare('SELECT COUNT(*) as c FROM mining_sessions').first(),
          env.DB.prepare('SELECT username,wallet_address,points,total_mined,mining_power,active_referral_count,created_at,login_method,is_banned FROM users ORDER BY created_at DESC LIMIT 10').all()
        ]);
        return json({ users: uc?.c||0, total_mined: tm?.s||0, tasks: tc?.c||0, sessions: mc?.c||0, recent: recent.results });
      }
      if (path === '/api/admin/transactions' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT t.*, u.username FROM transactions t LEFT JOIN users u ON t.user_id = u.id ORDER BY t.created_at DESC LIMIT 100').all();
        return json(results);
      }
      if (path === '/api/admin/mining' && req.method === 'GET') {
        const { results } = await env.DB.prepare('SELECT ms.*, u.username FROM mining_sessions ms LEFT JOIN users u ON ms.user_id = u.id ORDER BY ms.started_at DESC LIMIT 50').all();
        return json(results);
      }
    }

    return err('Not found', 404);
  }
};

