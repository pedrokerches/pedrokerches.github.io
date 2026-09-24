const { isAuthenticated } = require('./api/auth/_session');

module.exports = async (request) => {
  const path = new URL(request.url).pathname;
  if (path === '/admin' || path.startsWith('/admin/')) {
    if (!isAuthenticated({ headers: Object.fromEntries(request.headers) })) {
      return Response.redirect(new URL('/admin/login', request.url), 302);
    }
  }
  return undefined;
};
