const DOH_URL = 'https://security.cloudflare-dns.com/dns-query';
const CONTENT_TYPE_DNS = 'application/dns-message';
const CONTENT_TYPE_JSON = 'application/dns-json';

// 自定义 DNS 路径
const DNS_PATH = '/dns-query';

export default {
    async fetch(request, env, ctx) {
        return handleRequest(request, env);
    },
};


// 判断是否为合法的 DoH 请求
function isValidDohRequest(method, headers, searchParams) {

    if (method === 'GET' && searchParams.has('dns')) return true;

    if (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) return true;

    if (method === 'GET' && headers.get('Accept') === CONTENT_TYPE_JSON) return true;
    return false;
}

async function handleRequest(request, env) {
    const { method, headers, url } = request;
    const { pathname, searchParams } = new URL(url);


    if (pathname === DNS_PATH) {

        if (isValidDohRequest(method, headers, searchParams)) {
            return handleDohRequest(request);
        }

        return serveStatic(env, request);
    }


    return serveStatic(env, request);
}


async function handleDohRequest(request) {
    const { method, headers, url } = request;
    const { searchParams } = new URL(url);

    let response = new Response(null, { status: 404 });

    if (method === 'GET' && searchParams.has('dns')) {
        response = fetch(`${DOH_URL}?dns=${searchParams.get('dns')}`, {
            method: 'GET',
            headers: { 'Accept': CONTENT_TYPE_DNS },
        });
    } else if (method === 'POST' && headers.get('content-type') === CONTENT_TYPE_DNS) {
        response = fetch(DOH_URL, {
            method: 'POST',
            headers: {
                'Accept': CONTENT_TYPE_DNS,
                'Content-Type': CONTENT_TYPE_DNS,
            },
            body: request.body,
        });
    } else if (method === 'GET' && headers.get('Accept') === CONTENT_TYPE_JSON) {
        const queryString = new URL(url).search;
        response = fetch(`${DOH_URL}${queryString}`, {
            method: 'GET',
            headers: { 'Accept': CONTENT_TYPE_JSON },
        });
    }

    return response;
}


async function serveStatic(env, request) {
    if (typeof env.ASSETS !== 'undefined') {
        return env.ASSETS.fetch(request);
    }
    // 降级方案请求根目录的 index.html
    return fetch(new URL('/', request.url).href + 'index.html');
}