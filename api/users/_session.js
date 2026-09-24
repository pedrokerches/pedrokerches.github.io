const crypto = require('node:crypto');

const COOKIE = 'sites_makers_user';
const MAX_AGE = 60 * 60 * 24 * 30;

function cookies(header = '') {
  return Object.fromEntries(header.split(';').map(part => {
    const i = part.indexOf('=');
    return i < 0 ? [part.trim(), ''] : [part.slice(0, i).trim(), decodeURIComponent(part.slice(i + 1).trim())];
  }).filter(([key]) => key));
}

function secret() {
  const value = process.env.USER_SESSION_SECRET;
  if (!value) throw new Error('USER_SESSION_SECRET is not configured');
  return value;
}

function sign(value) {
  return crypto.createHmac('sha256', secret()).update(value).digest('base64url');
}

function createSession(user) {
  const payload = Buffer.from(JSON.stringify({
    sub: user.id,
    name: user.name,
    email: user.email,
    exp: Math.floor(Date.now() / 1000) + MAX_AGE
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function getSession(req) {
  const value = cookies(req.headers.cookie || '')[COOKIE];
  if (!value) return null;
  const [payload, signature] = value.split('.');
  if (!payload || !signature) return null;
  const a = Buffer.from(signature);
  const b = Buffer.from(sign(payload));
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.sub && Number(data.exp) > Math.floor(Date.now() / 1000) ? data : null;
  } catch {
    return null;
  }
}

function setSession(res, req, user) {
  const secure = req.headers['x-forwarded-proto'] === 'https' || !req.headers['x-forwarded-proto'];
  res.setHeader('Set-Cookie', `${COOKIE}=${createSession(user)}; Max-Age=${MAX_AGE}; Path=/; HttpOnly;${secure ? ' Secure;' : ''} SameSite=Lax`);
}

function clearSession(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

module.exports = { getSession, setSession, clearSession };
