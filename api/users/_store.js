const crypto = require('node:crypto');

function config() {
  const url = process.env.KV_REST_API_URL;
  const token = process.env.KV_REST_API_TOKEN;
  if (!url || !token) throw new Error('User database is not configured');
  return { url: url.replace(/\/$/, ''), token };
}

async function kv(command, ...args) {
  const { url, token } = config();
  const response = await fetch(`${url}/${command}/${args.map(value => encodeURIComponent(value)).join('/')}`, {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) throw new Error('User database request failed');
  const result = await response.json();
  return result.result;
}

function normalizeEmail(email) {
  return String(email || '').trim().toLowerCase();
}

function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  return new Promise((resolve, reject) => crypto.scrypt(password, salt, 64, (error, derived) => {
    if (error) return reject(error);
    resolve({ salt, hash: derived.toString('hex') });
  }));
}

function verifyPassword(password, user) {
  return new Promise((resolve, reject) => crypto.scrypt(password, user.salt, 64, (error, derived) => {
    if (error) return reject(error);
    const expected = Buffer.from(user.hash, 'hex');
    resolve(expected.length === derived.length && crypto.timingSafeEqual(expected, derived));
  }));
}

async function getUser(email) {
  return kv('get', `sites_makers_user_email:${normalizeEmail(email)}`);
}

async function saveUser(user) {
  await kv('set', `sites_makers_user_email:${user.email}`, JSON.stringify(user));
}

module.exports = { getUser, saveUser, hashPassword, verifyPassword, normalizeEmail };
