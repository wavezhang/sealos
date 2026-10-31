import { NextApiRequest, NextApiResponse } from 'next';
import { verifyGlobalToken } from '@/services/backend/auth';
import { jsonRes } from '@/services/backend/response';
import { SHARED_AUTH_COOKIE_NAME } from '@/utils/cookieUtils';

const COOKIE_MAX_AGE = 60 * 60 * 24 * 7;

const getHostname = (req: NextApiRequest) => {
  const host = req.headers.host || '';
  return host.split(':')[0].toLowerCase();
};

// Cross-region SSO needs the cookie on the parent domain (e.g. .sealos.io).
// Localhost, IPs and wildcard-DNS dev domains get a host-only cookie.
const getSharedCookieDomain = (req: NextApiRequest): string | undefined => {
  const hostname = getHostname(req);
  if (!hostname || hostname === 'localhost') return undefined;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) || hostname.includes(':')) return undefined;
  if (hostname.endsWith('.localhost') || hostname.endsWith('.nip.io') || hostname.endsWith('.sslip.io')) {
    return undefined;
  }
  const labels = hostname.split('.');
  // Never set a cookie on a bare registrable domain; require a subdomain.
  if (labels.length < 3) return undefined;
  return '.' + labels.slice(-2).join('.');
};

const isHttpsRequest = (req: NextApiRequest) => {
  const forwardedProto = req.headers['x-forwarded-proto'];
  const proto = Array.isArray(forwardedProto) ? forwardedProto[0] : forwardedProto;
  return proto === 'https' || Boolean((req.socket as { encrypted?: boolean })?.encrypted);
};

const serializeAuthCookie = (
  value: string,
  domain: string | undefined,
  secure: boolean,
  maxAge: number
) =>
  [
    `${SHARED_AUTH_COOKIE_NAME}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    `Max-Age=${maxAge}`,
    ...(domain ? [`Domain=${domain}`] : []),
    ...(secure ? ['Secure'] : [])
  ].join('; ');

const readAuthorizationToken = (req: NextApiRequest) => {
  const header = req.headers.authorization;
  if (!header) return null;
  try {
    return decodeURIComponent(header);
  } catch {
    return null;
  }
};

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  try {
    if (req.method === 'DELETE') {
      const domain = getSharedCookieDomain(req);
      const secure = isHttpsRequest(req);
      // Clear both the domain-scoped and host-only variants.
      const expirations = [serializeAuthCookie('', domain, secure, 0)];
      if (domain) expirations.push(serializeAuthCookie('', undefined, secure, 0));
      res.setHeader('Set-Cookie', expirations);
      return jsonRes(res, { code: 200, message: 'Successfully' });
    }

    if (req.method !== 'POST') {
      return res.status(405).json({ code: 405, message: 'Method not allowed', data: null });
    }

    const token = readAuthorizationToken(req);
    if (!token) {
      return res.status(401).json({ code: 401, message: 'Unauthorized', data: null });
    }
    const payload = await verifyGlobalToken(req.headers);
    if (!payload) {
      return res.status(401).json({ code: 401, message: 'Unauthorized', data: null });
    }

    const domain = getSharedCookieDomain(req);
    res.setHeader(
      'Set-Cookie',
      serializeAuthCookie(token, domain, isHttpsRequest(req), COOKIE_MAX_AGE)
    );
    return jsonRes(res, { code: 200, message: 'Successfully' });
  } catch (error) {
    console.error('sharedCookie error:', error);
    return res.status(500).json({ code: 500, message: 'Failed to update session cookie', data: null });
  }
}
