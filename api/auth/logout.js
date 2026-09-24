const { clearSession } = require('./_session');

module.exports = (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).json({ error: 'Método não permitido.' });
  }
  clearSession(res);
  return res.status(200).json({ authenticated: false });
};
