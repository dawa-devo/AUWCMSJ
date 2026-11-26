const app = require('../backend/server');

module.exports = (req, res) => {
    const rewrittenUrl = new URL(req.url || '/', 'http://localhost');
    const apiPath = rewrittenUrl.searchParams.get('__api_path');

    if (apiPath !== null) {
        const pathSegments = apiPath.split('/').filter(Boolean);
        if (!pathSegments.length || pathSegments.some((segment) => segment === '.' || segment === '..')) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ message: 'Invalid API route.' }));
            return;
        }

        rewrittenUrl.searchParams.delete('__api_path');
        const query = rewrittenUrl.search;
        req.url = `/api/${pathSegments.map((segment) => encodeURIComponent(segment)).join('/')}${query}`;
    }

    return app(req, res);
};
