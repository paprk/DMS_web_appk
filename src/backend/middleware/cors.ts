import { getConfig } from '../config/context';

export function corsMiddleware(request: Request): Response {
  const origin = request.headers.get('origin');
  const config = getConfig();
  const responseHeaders: Record<string, string> = {
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };

  // Defensive check: ensure allowedOrigins is defined and is an array
  const allowedOrigins = config?.security?.allowedOrigins;
  if (!Array.isArray(allowedOrigins)) {
    // Fallback to default behavior if configuration is malformed
    responseHeaders['Access-Control-Allow-Origin'] = '*';
    responseHeaders['Access-Control-Allow-Credentials'] = 'false';
  } else {
    // Check if the origin is allowed
    if (allowedOrigins.includes('*') ||
        (origin && allowedOrigins.includes(origin))) {
      responseHeaders['Access-Control-Allow-Origin'] = origin || '*';
      responseHeaders['Access-Control-Allow-Credentials'] = 'true';
    }
  }

  // Handle preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      status: 200,
      headers: responseHeaders
    });
  }

  return new Response(null, { headers: responseHeaders });
}

/**
 * Adds CORS headers to a response
 */
export function addCorsHeaders(response: Response, request: Request): Response {
  const origin = request.headers.get('origin');
  const config = getConfig();
  const responseHeaders = new Headers(response.headers);

  // Defensive check: ensure allowedOrigins is defined and is an array
  const allowedOrigins = config?.security?.allowedOrigins;
  if (!Array.isArray(allowedOrigins)) {
    // Fallback to default behavior if configuration is malformed
    responseHeaders.set('Access-Control-Allow-Origin', '*');
    responseHeaders.set('Access-Control-Allow-Credentials', 'false');
  } else {
    // Check if the origin is allowed
    if (allowedOrigins.includes('*') ||
        (origin && allowedOrigins.includes(origin))) {
      responseHeaders.set('Access-Control-Allow-Origin', origin || '*');
      responseHeaders.set('Access-Control-Allow-Credentials', 'true');
    }
  }

  responseHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  responseHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}
