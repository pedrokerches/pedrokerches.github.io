const crypto = require('node:crypto');

const COOKIE = 'sites_makers_admin';
const MAX_AGE = 60 * 60 * 8;

function secret() {
  const email = process.env.ADMIN_EMAIL || '';
  const password = process.env.ADMIN_PASSWORD || '';
  return crypto.createHash('sha256').update(`${email}\0${password}`).digest();
}

function sign(value) {
  return crypto.createHmac('sha256', secret()).update(value).digest('base64url');
}

function createSession() {
  const payload = Buffer.from(JSON.stringify({
    sub: 'admin',
    exp: Math.floor(Date.now() / 1000) + MAX_AGE
  })).toString('base64url');
  return `${payload}.${sign(payload)}`;
}

function verifySession(value) {
  if (!value) return false;
  const [payload, signature] = value.split('.');
  if (!payload || !signature) return false;
  const expected = sign(payload);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return false;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    return data.sub === 'admin' && Number(data.exp) > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function cookies(header = '') {
  return Object.fromEntries(header.split(';').map(part => {
    const i = part.indexOf('=');
    return i < 0 ? [part.trim(), ''] : [part.slice(0, i).trim(), part.slice(i + 1).trim()];
  }).filter(([key]) => key));
}

function isAuthenticated(req) {
  return verifySession(cookies(req.headers.cookie)[COOKIE]);
}

function setSession(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=${createSession()}; Max-Age=${MAX_AGE}; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

function clearSession(res) {
  res.setHeader('Set-Cookie', `${COOKIE}=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Lax`);
}

module.exports = { COOKIE, MAX_AGE, createSession, verifySession, isAuthenticated, setSession, clearSession };
