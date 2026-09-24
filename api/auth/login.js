const crypto = require('node:crypto');
const { setSession } = require('./_session');

function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

function body(req) {
  if (req.body && typeof req.body === 'object') return req.body;
  if (typeof req.body === 'string') {
    try { return JSON.parse(req.body); } catch { return {}; }
  }
  return {};
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido.' });
  }

  // Secrets are read only by this server-side function. They are never sent
  // to the browser or embedded in the public source code.
  const configured = typeof process.env.ADMIN_EMAIL === 'string'
    && process.env.ADMIN_EMAIL.length > 0
    && typeof process.env.ADMIN_PASSWORD === 'string'
    && process.env.ADMIN_PASSWORD.length > 0;
  if (!configured) {
    return res.status(503).json({ error: 'Autenticação não configurada no ambiente do servidor.' });
  }

  const { email, password } = body(req);
  const valid = sameSecret(email, process.env.ADMIN_EMAIL)
    && sameSecret(password, process.env.ADMIN_PASSWORD);
  if (!valid) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });

  setSession(res, req);
  return res.status(200).json({ authenticated: true });
};
