const { isAuthenticated } = require('./_session');

module.exports = (req, res) => {
  if (req.method !== 'GET') {
    res.setHeader('Allow', 'GET');
    return res.status(405).json({ error: 'Método não permitido.' });
  }
  return res.status(isAuthenticated(req) ? 200 : 401).json({ authenticated: isAuthenticated(req) });
};
