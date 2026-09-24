const crypto = require('node:crypto');
const { setSession } = require('./_session');

function sameSecret(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && crypto.timingSafeEqual(left, right);
}

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido.' });
  }
  const { email, password } = req.body || {};
  const valid = sameSecret(email, process.env.ADMIN_EMAIL) && sameSecret(password, process.env.ADMIN_PASSWORD);
  if (!valid) return res.status(401).json({ error: 'E-mail ou senha incorretos.' });
  setSession(res);
  return res.status(200).json({ authenticated: true });
};
