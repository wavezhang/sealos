import Cookies, { CookieAttributes } from 'js-cookie';

export const setCookie = (key: string, value: string, options?: CookieAttributes) => {
  Cookies.set(key, value, options);
};

export const getCookie = (key: string) => {
  return Cookies.get(key);
};

export const removeCookie = (key: string) => {
  Cookies.remove(key);
};

// Shared Cookie configuration
const SHARED_AUTH_COOKIE_NAME = 'sealos_auth_token';

// Get shared cookie domain (e.g., usw.sealos.io -> .sealos.io)
export const getSharedCookieDomain = (): string | undefined => {
  if (typeof window === 'undefined') return undefined;
  const hostname = window.location.hostname;
  if (hostname === 'localhost' || hostname === '127.0.0.1') return undefined;
  const parts = hostname.split('.');
  if (parts.length >= 2) return '.' + parts.slice(-2).join('.');
  return undefined;
};

// The shared auth cookie is issued by /api/auth/sharedCookie as HttpOnly; the
// browser must never write it from JavaScript. These helpers only clean up
// copies created by older releases.
const removeLegacyCookieCopies = (): void => {
  const domain = getSharedCookieDomain();
  if (domain) Cookies.remove(SHARED_AUTH_COOKIE_NAME, { path: '/', domain });
  Cookies.remove(SHARED_AUTH_COOKIE_NAME, { path: '/' });
};

const postSharedAuthCookie = async (token: string) => {
  const response = await fetch('/api/auth/sharedCookie', {
    method: 'POST',
    credentials: 'same-origin',
    headers: { Authorization: encodeURIComponent(token) }
  });
  return response.ok;
};

// Set shared authentication cookie. The token is handed to the server, which
// responds with an HttpOnly; SameSite=Lax; Secure (on HTTPS) cookie.
export const setSharedAuthCookie = (globalToken: string): void => {
  if (typeof window === 'undefined') return;
  if (!globalToken) {
    clearSharedAuthCookie();
    return;
  }
  removeLegacyCookieCopies();
  postSharedAuthCookie(globalToken).catch((error) => {
    console.error('Failed to set shared auth cookie:', error);
  });
};

// Clear shared authentication cookie (host-only and parent-domain variants).
export const clearSharedAuthCookie = (): void => {
  if (typeof window === 'undefined') return;
  removeLegacyCookieCopies();
  fetch('/api/auth/sharedCookie', {
    method: 'DELETE',
    credentials: 'same-origin'
  }).catch((error) => {
    console.error('Failed to clear shared auth cookie:', error);
  });
};

// Older releases stored the global token in a JavaScript-readable cookie.
// Re-issue it as HttpOnly before removing the legacy copy.
export const migrateLegacySharedAuthCookie = (): void => {
  if (typeof window === 'undefined') return;
  const legacyToken = Cookies.get(SHARED_AUTH_COOKIE_NAME);
  if (!legacyToken) return;
  postSharedAuthCookie(legacyToken)
    .then((ok) => {
      if (ok) removeLegacyCookieCopies();
    })
    .catch((error) => {
      console.error('Failed to migrate shared auth cookie:', error);
    });
};

export { SHARED_AUTH_COOKIE_NAME };
