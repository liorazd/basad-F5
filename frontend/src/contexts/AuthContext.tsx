import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import { APIService } from '@/services/api.service';

export type Role = 'admin' | 'anonymous';

interface AuthValue {
  role: Role;
  username: string | null;
  email: string | null;
  loading: boolean;
  /**
   * Epoch seconds when the client-side session expires (backend TTL minus a
   * safety margin). This is what the countdown UI and auto-logout timer use.
   */
  expiresAt: number | null;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthValue | null>(null);

const EXPIRY_CHECK_INTERVAL_MS = 30 * 1000;

export const AuthProvider = ({ children }: { children: ReactNode }) => {
  const [role, setRole] = useState<Role>('anonymous');
  const [username, setUsername] = useState<string | null>(null);
  const [email, setEmail] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [expiresAt, setExpiresAt] = useState<number | null>(APIService.getEffectiveExpiresAt());
  const roleRef = useRef<Role>('anonymous');
  roleRef.current = role;

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await APIService.whoami();
      setRole(data.role);
      setUsername(data.username);
      setEmail(data.email);
      setExpiresAt(APIService.getEffectiveExpiresAt());
    } catch {
      // /me now answers 200 'anonymous' when nobody is logged in, so this only
      // fires on a real transport/backend failure. Fail closed to anonymous.
      setRole('anonymous');
      setUsername(null);
      setEmail(null);
      setExpiresAt(null);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Poll the locally-known token TTL. When it elapses we forcibly log out
  // so a stale 'admin' role can't sneak the user past RequireAuth into a
  // page that will then 401 on its first API call.
  useEffect(() => {
    const tick = () => {
      if (roleRef.current !== 'admin') return;
      if (APIService.isTokenExpired()) {
        APIService.expireSession();
      }
    };
    const id = window.setInterval(tick, EXPIRY_CHECK_INTERVAL_MS);
    return () => window.clearInterval(id);
  }, []);

  return (
    <AuthContext.Provider value={{ role, username, email, loading, expiresAt, refresh }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error('useAuth must be used inside <AuthProvider>');
  return ctx;
};
