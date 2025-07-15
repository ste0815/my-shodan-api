import { SignJWT, jwtVerify } from 'jose';

const CACHE_TTL = 1800; // 缓存30分钟
const CACHE_PREFIX = "shodan:";

export default {
  async fetch(request, env, ctx) {
    // 预检请求处理
    if (request.method === 'OPTIONS') {
      return handleOptions(request, env);
    }

    const url = new URL(request.url);
    const { pathname } = url;

    // 新增：登录路由，这是唯一不需要令牌的 POST 接口
    if (pathname === '/api/login' && request.method === 'POST') {
      return handleLogin(request, env);
    }

    // JWT 验证中间件
    const authHeader = request.headers.get('Authorization') || '';
    const token = authHeader.replace(/^Bearer\s+/i, '');

    if (!token) {
      return jsonResponse({ success: false, error: 'Unauthorized. Token not provided.' }, { status: 401, env });
    }

    try {
      const secret = new TextEncoder().encode(env.JWT_SECRET);
      await jwtVerify(token, secret);
    } catch (err) {
      return jsonResponse({ success: false, error: 'Unauthorized. Invalid or expired token.' }, { status: 401, env });
    }

    // API 使用速率限制
    if (env.API_RATELIMITER) {
      const ip = request.headers.get('CF-Connecting-IP');
      if (ip) {
        const { success } = await env.API_RATELIMITER.limit({ key: ip });
        if (!success) {
          return jsonResponse({ success: false, error: 'Too Many Requests. API usage rate limit exceeded.' }, { status: 429, env });
        }
      }
    }
    
    // --- 路由逻辑 (保持不变) ---
    if (request.method === 'GET') {
      if (pathname === '/info' || pathname === '/api/info') {
        return handleApiInfoRequest(request, env);
      }
      if (pathname.startsWith('/search')) {
        return handleSearchRequest(request, env, ctx);
      }
      const hostMatch = pathname.match(/^\/shodan\/host\/(.+)$/);
      if (hostMatch) {
        const ip = decodeURIComponent(hostMatch[1]);
        return handleHostRequest(ip, env);
      }
      if (pathname.startsWith('/domain/')) {
        return handleDomainRequest(request, env);
      }
      if (pathname === '/myip' || pathname === '/api/myip') {
        return handleMyIpGetRequest(request, env);
      }
    }

    if (request.method === 'POST') {
      if (pathname === '/ipinfo' || pathname === '/api/ipinfo') {
        return handleIpInfoPostRequest(request, env);
      }
    }
    
    return jsonResponse({ success: false, error: `Path ${pathname} with method ${request.method} not found.` }, { status: 404, env });
  },
};

/**
 * 【已更新】处理登录请求的函数，增加了防暴力破解逻辑
 * @param {Request} request
 * @param {object} env
 */
async function handleLogin(request, env) {
  // 【新增】防暴力破解逻辑
  if (env.LOGIN_RATELIMITER) {
    const ip = request.headers.get('CF-Connecting-IP');
    if (ip) {
      // 使用专门的登录限制器
      const { success } = await env.LOGIN_RATELIMITER.limit({ key: ip });
      if (!success) {
        // 如果请求过于频繁，直接拒绝，不进行密码验证
        return jsonResponse({ success: false, error: 'Too many login attempts. Please try again later.' }, { status: 429, env });
      }
    }
  }

  try {
    const { password } = await request.json();

    if (!password) {
      return jsonResponse({ success: false, error: 'Password is required.' }, { status: 400, env });
    }

    const correctPassword = env.APP_PASSWORD;
    if (!correctPassword) {
        return jsonResponse({ success: false, error: 'Password not configured on the server.' }, { status: 500, env });
    }

    if (password !== correctPassword) {
      // 密码错误，返回 401。此时该 IP 的失败计数会增加。
      return jsonResponse({ success: false, error: 'Invalid password.' }, { status: 401, env });
    }

    // 密码正确，生成 JWT
    const secret = new TextEncoder().encode(env.JWT_SECRET);
    const token = await new SignJWT({})
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime('24h')
      .sign(secret);

    return jsonResponse({ success: true, token }, { status: 200, env });

  } catch (error) {
    console.error("Error in handleLogin:", error);
    return jsonResponse({ success: false, error: 'An internal server error occurred during login.' }, { status: 500, env });
  }
}

async function handleApiInfoRequest(request, env) {
  try {
    const shodanApiKey = env.SHODAN_API_KEY;
    if (!shodanApiKey) {
      return jsonResponse({ success: false, error: 'Server configuration error: Shodan API key not found.'}, { status: 500, env });
    }
    
    const apiInfoUrl = `https://api.shodan.io/api-info?key=${shodanApiKey}`;
    const response = await fetch(apiInfoUrl);
    
    let data;
    try {
      data = await response.json();
    } catch (e) {
      data = { error: `Shodan API returned non-JSON response. Status: ${response.status}` };
    }

    if (!response.ok) {
      return jsonResponse({ success: false, ...data }, { status: response.status, env });
    }

    const filteredData = { success: true, query_credits: data.query_credits };
    return jsonResponse(filteredData, { status: 200, env });

  } catch(error) {
    console.error("Error in handleApiInfoRequest:", error);
    return jsonResponse({ success: false, error: 'An internal server error occurred.' }, { status: 500, env });
  }
}

async function handleSearchRequest(request, env, ctx) {
  try {
    const url = new URL(request.url);
    const query = url.searchParams.get('q');
    const page = parseInt(url.searchParams.get('page') || '1', 10);

    if (!query) {
      return jsonResponse({ success: false, error: 'The "q" query parameter is required for search.' }, { status: 400, env });
    }

    const cacheKey = `${CACHE_PREFIX}${encodeURIComponent(query)}:${page}`;
    const cached = await env.CACHE_KV.get(cacheKey, { type: 'json' });
    if (cached) {
      return jsonResponse({ ...cached, _cache: true }, { env });
    }

    const shodanApiKey = env.SHODAN_API_KEY;
    const searchUrl = new URL('https://api.shodan.io/shodan/host/search');
    searchUrl.searchParams.set('key', shodanApiKey);
    searchUrl.searchParams.set('query', query);
    searchUrl.searchParams.set('page', page);
    const finalUrl = searchUrl.toString().replace(/\+/g, '%20');

    const response = await fetch(finalUrl);
    
    let data;
    try {
      data = await response.json();
    } catch (e) {
      data = { error: `Shodan API returned non-JSON response. Status: ${response.status}` };
    }

    if (!response.ok) {
      return jsonResponse({ success: false, ...data }, { status: response.status, env });
    }

    ctx.waitUntil(env.CACHE_KV.put(cacheKey, JSON.stringify(data), { expirationTtl: CACHE_TTL }));
    return jsonResponse({ success: true, ...data }, { status: 200, env });

  } catch (error) {
    console.error("Error in handleSearchRequest:", error);
    return jsonResponse({ success: false, error: 'An internal server error occurred.' }, { status: 500, env });
  }
}

async function handleHostRequest(targetIp, env) {
  try {
    if (!targetIp || !isValidIpAddress(targetIp)) {
      return jsonResponse({ success: false, error: 'Invalid or missing IP address in URL path.' }, { status: 400, env });
    }

    const shodanApiKey = env.SHODAN_API_KEY;
    const shodanApiUrl = `https://api.shodan.io/shodan/host/${targetIp}?key=${shodanApiKey}`;
    
    const response = await fetch(shodanApiUrl);

    let rawData;
    try {
      rawData = await response.json();
    } catch (e) {
      rawData = { error: `Shodan API returned non-JSON response. Status: ${response.status}` };
    }

    if (!response.ok) {
      return jsonResponse({ success: false, ...rawData }, { status: response.status, env });
    }

    const transformedData = {
      success: true,
      query: { ip: rawData.ip_str, timestamp: new Date().toISOString() },
      basicInfo: { country: rawData.country_name || null, countryCode: rawData.country_code || null, city: rawData.city || null, region: rawData.region_code || null, organization: rawData.org || null, isp: rawData.isp || null, asn: rawData.asn || null, hostnames: rawData.hostnames || [], tags: rawData.tags || [] },
      vulnerabilities: (rawData.vulns || []).map(vuln => ({ cve: vuln })),
      openPorts: (rawData.data || []).map(service => ({ port: service.port, transport: service.transport, product: service.product || null, version: service.version || null, http: service.http || null, ssl: service.ssl || null })),
      rawData: rawData,
    };
    return jsonResponse(transformedData, { status: 200, env });

  } catch (error) {
    console.error(`Error in handleHostRequest for IP ${targetIp}:`, error);
    return jsonResponse({ success: false, error: 'An internal server error occurred.' }, { status: 500, env });
  }
}

async function handleDomainRequest(request, env) {
  try {
    const url = new URL(request.url);
    const pathSegments = url.pathname.split('/');
    const domain = pathSegments[pathSegments.length - 1];
    
    if (!domain || !isValidDomain(domain)) {
      return jsonResponse({ success: false, error: 'Invalid or missing domain name.' }, { status: 400, env });
    }

    const shodanApiKey = env.SHODAN_API_KEY;
    const domainApiUrl = `https://api.shodan.io/dns/domain/${domain}?key=${shodanApiKey}`;
    
    const response = await fetch(domainApiUrl);
    
    let data;
    try {
      data = await response.json();
    } catch (e) {
      data = { error: `Shodan API returned non-JSON response. Status: ${response.status}` };
    }
    
    if (!response.ok) {
      return jsonResponse({ success: false, ...data }, { status: response.status, env });
    }

    return jsonResponse({ success: true, ...data }, { status: 200, env });

  } catch (error) {
    console.error("Error in handleDomainRequest:", error);
    return jsonResponse({ success: false, error: 'An internal server error occurred.' }, { status: 500, env });
  }
}

async function handleMyIpGetRequest(request, env) {
  const clientIP = request.headers.get("CF-Connecting-IP") || "Unknown";
  return jsonResponse({ success: true, ip: clientIP }, { env });
}

async function handleIpInfoPostRequest(request, env) {
  try {
    const requestData = await request.json();
    const ip = requestData.ip;

    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ip || !ipRegex.test(ip)) {
      return jsonResponse({ error: "Invalid IP address format" }, { status: 400, env });
    }
    if (isReservedIP(ip)) {
      return jsonResponse({ error: "Querying private or reserved IP addresses is not supported" }, { status: 400, env });
    }

    const ipLocResponse = await fetch(`https://apimobile.meituan.com/locate/v2/ip/loc?rgeo=true&ip=${ip}`);
    if (!ipLocResponse.ok) {
      return jsonResponse({ error: `Geolocation API request failed: ${ipLocResponse.status}` }, { status: 502, env });
    }
    
    const ipLocData = await ipLocResponse.json();
    if (!ipLocData.data) {
      return jsonResponse({ error: "Could not retrieve IP geolocation information" }, { status: 404, env });
    }
    
    const { lng, lat } = ipLocData.data;
    if (!lng || !lat) {
      return jsonResponse({ error: "Could not retrieve latitude/longitude information" }, { status: 404, env });
    }

    const detailResponse = await fetch(`https://apimobile.meituan.com/group/v1/city/latlng/${lat},${lng}?tag=0`);
    if (!detailResponse.ok) {
      return jsonResponse({ error: `Detailed address API request failed: ${detailResponse.status}` }, { status: 502, env });
    }

    const detailData = await detailResponse.json();
    const result = {
      success: true,
      ip,
      location: {
        country: ipLocData.data?.rgeo?.country || "",
        province: ipLocData.data?.rgeo?.province || "",
        city: ipLocData.data?.rgeo?.city || "",
        district: ipLocData.data?.rgeo?.district || "",
        detail: detailData.data?.detail || "",
        lat,
        lng
      }
    };
    return jsonResponse(result, { env });

  } catch (error) {
    console.error("Error in handleIpInfoPostRequest:", error);
    return jsonResponse({ error: "An internal server error occurred." }, { status: 500, env });
  }
}

// --- 辅助函数和工具 ---

function jsonResponse(data, options = {}) {
  const { status = 200, env = {} } = options;
  const headers = { 
    'Content-Type': 'application/json', 
    ...getCorsHeaders(env), 
    'X-Content-Type-Options': 'nosniff' 
  };
  return new Response(JSON.stringify(data, null, 2), { status, headers });
}

function handleOptions(request, env) {
  const corsHeaders = getCorsHeaders(env);
  return new Response(null, { 
    headers: { 
      ...corsHeaders, 
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 
      'Access-Control-Allow-Headers': 'Content-Type, Authorization', 
      'Access-Control-Max-Age': '86400' 
    } 
  });
}

function getCorsHeaders(env) {
  const allowedOrigin = env.ALLOWED_ORIGIN || 'https://hunter.arksec.net';
  return { 'Access-Control-Allow-Origin': allowedOrigin };
}

function isReservedIP(ip) {
  const octets = ip.split('.').map(Number);
  if (octets[0] === 10) return true;
  if (octets[0] === 172 && (octets[1] >= 16 && octets[1] <= 31)) return true;
  if (octets[0] === 192 && octets[1] === 168) return true;
  if (octets[0] === 169 && octets[1] === 254) return true;
  if (octets[0] === 127) return true;
  if (octets[0] === 0) return true;
  if (octets[0] === 100 && (octets[1] >= 64 && octets[1] <= 127)) return true;
  if (octets[0] === 192 && octets[1] === 0 && octets[2] === 0) return true;
  if ((octets[0] === 192 && octets[1] === 0 && octets[2] === 2) || (octets[0] === 198 && octets[1] === 51 && octets[2] === 100) || (octets[0] === 203 && octets[1] === 0 && octets[2] === 113)) return true;
  if (octets[0] >= 224 && octets[0] <= 239) return true;
  if (octets[0] >= 240) return true;
  return false;
}

function isValidIpAddress(ip) {
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  const ipv6Regex = /(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))/;
  return ipv4Regex.test(ip) || ipv6Regex.test(ip);
}

function isValidDomain(domain) {
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  return domainRegex.test(domain);
}
