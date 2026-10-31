import { Session, sessionKey } from '@/types';
import { OauthProvider } from '@/types/user';
import { create } from 'zustand';
import { persist } from 'zustand/middleware';
import { immer } from 'zustand/middleware/immer';
import { nanoid } from 'nanoid';
import { setSharedAuthCookie } from '@/utils/cookieUtils';
import { clearWebAnalyticsIdentity } from '@/utils/app-visitor-link';

export type OauthAction = 'LOGIN' | 'BIND' | 'UNBIND' | 'PROXY';

const OAUTH_STATE_STORAGE_PREFIX = 'sealos_oauth_state:';
const OAUTH_STATE_TTL_MS = 10 * 60 * 1000;

type StoredOauthState = {
  state: string;
  action: OauthAction;
  provider?: OauthProvider;
  domainState?: string;
  createdAt: number;
};

export type ComparedOauthState = {
  action: string;
  statePayload: string[];
  provider?: OauthProvider;
};

// CSPRNG nonce. `randomUUID` requires a secure context, so fall back to
// getRandomValues (available on plain HTTP too).
const createOauthState = (): string => {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
};

type SessionState = {
  session?: Session; // session.token is app token
  token: string; // region token (used for API requests)
  globalToken: string; // global token (used for cross-domain auth cookie)
  provider?: OauthProvider;
  firstUse: Date | null;
  hasEverLoggedIn: boolean;
  setSession: (ss: Session) => void;
  setSessionProp: <T extends keyof Session>(key: T, value: Session[T]) => void;
  delSession: () => void;
  setFirstUse: (d: Date | null) => void;
  setHasEverLoggedIn: (value: boolean) => void;
  isUserLogin: () => boolean;

  generateState: (action?: OauthAction, domainState?: string, provider?: OauthProvider) => string;
  compareState: (state: string) => ComparedOauthState | null;
  lastSigninProvier?: string;
  setLastSigninProvider: (provider?: string) => void;
  setProvider: (provider?: OauthProvider) => void;
  setToken: (token: string, rememberMe?: boolean) => void; // Sets region token
  setGlobalToken: (token: string) => void; // Sets global token and cookie
  lastWorkSpaceId: string;
  setWorkSpaceId: (id: string) => void;
  setGuestSession: () => void;
  isGuest: () => boolean;
  showGuestLoginModal: boolean;
  openGuestLoginModal: () => void;
  closeGuestLoginModal: () => void;
};

const useSessionStore = create<SessionState>()(
  persist(
    immer((set, get) => ({
      session: undefined,
      provider: undefined,
      lastSigninProvier: undefined,
      firstUse: null,
      hasEverLoggedIn: false,
      token: '', // Region token
      globalToken: '', // Global token
      lastWorkSpaceId: '',
      showGuestLoginModal: false,
      setFirstUse(d) {
        set({
          firstUse: d
        });
      },
      setHasEverLoggedIn(value) {
        set({
          hasEverLoggedIn: value
        });
      },
      setLastSigninProvider(provider?: string) {
        set({ lastSigninProvier: provider });
      },
      setSession: (ss: Session) => {
        if (get().session?.user?.userUid !== ss.user?.userUid) clearWebAnalyticsIdentity();
        set({ session: ss });
      },
      setSessionProp: <T extends keyof Session>(key: T, value: Session[T]) => {
        if (key === 'user' && get().session?.user?.userUid !== (value as Session['user'])?.userUid)
          clearWebAnalyticsIdentity();
        set((state) => {
          if (state.session) {
            state.session[key] = value;
          }
        });
      },
      delSession: () => {
        clearWebAnalyticsIdentity();
        set({ session: undefined });
      },
      isUserLogin: () => {
        const state = get();
        if (state.session?.isGuest) return false;
        return !!state.session?.user;
      },
      // The OAuth state is a CSPRNG nonce; the action/provider are kept in
      // sessionStorage and never read from the callback URL.
      generateState: (action = 'LOGIN', domainState, provider) => {
        const state = createOauthState();
        if (typeof window !== 'undefined') {
          const record: StoredOauthState = {
            state,
            action,
            provider,
            domainState,
            createdAt: Date.now()
          };
          window.sessionStorage.setItem(
            `${OAUTH_STATE_STORAGE_PREFIX}${state}`,
            JSON.stringify(record)
          );
        }
        return state;
      },
      compareState: (state: string) => {
        if (typeof window === 'undefined' || !state) return null;
        const key = `${OAUTH_STATE_STORAGE_PREFIX}${state}`;
        const raw = window.sessionStorage.getItem(key);
        if (!raw) return null;
        // Consume the record before validating so a replayed state can never
        // be accepted twice, even if validation fails below.
        window.sessionStorage.removeItem(key);
        try {
          const record = JSON.parse(raw) as StoredOauthState;
          if (record.state !== state) return null;
          if (Date.now() - record.createdAt > OAUTH_STATE_TTL_MS) return null;
          return {
            action: record.action,
            statePayload: record.domainState ? record.domainState.split('_') : [],
            provider: record.provider
          };
        } catch {
          return null;
        }
      },
      setProvider: (provider?: OauthProvider) => {
        set({ provider });
      },
      setToken: (token, rememberMe = false) => {
        // Sets region token (used for API requests)
        set({ token });
      },
      setGlobalToken: (token) => {
        // Sets global token and immediately updates cookie
        // Also sets state.token so API requests (getRegionToken, etc.) can use it
        set({ globalToken: token, token: token });
        if (typeof window !== 'undefined') {
          setSharedAuthCookie(token);
        }
      },
      setWorkSpaceId: (id) => {
        set({ lastWorkSpaceId: id });
      },
      setGuestSession: () => {
        clearWebAnalyticsIdentity();
        const guestId = `guest_${nanoid()}`;
        set({
          session: {
            isGuest: true,
            guestId,
            token: '',
            user: null,
            kubeconfig: '',
            subscription: null
          }
        });
      },
      isGuest: () => get().session?.isGuest || false,
      openGuestLoginModal: () => {
        set({ showGuestLoginModal: true });
      },
      closeGuestLoginModal: () => {
        set({ showGuestLoginModal: false });
      }
    })),
    {
      name: sessionKey,
      partialize: (state) => {
        const { showGuestLoginModal, globalToken, ...rest } = state;
        // Exclude globalToken and showGuestLoginModal from persistence
        // globalToken is ephemeral and should only exist in memory + cookie
        return rest;
      }
    }
  )
);

export default useSessionStore;
