module.exports = (req, res) => {
  res.status(410).json({ error: 'A autenticação administrativa foi desativada.' });
};
