import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import { F5VIP } from '@/types/vip';
import { APIService } from '@/services/api.service';
import { useAuth } from '@/contexts/AuthContext';

interface VIPsContextValue {
  vips: F5VIP[];
  loading: boolean;
  error: string | null;
  lastLoadedAt: number | null;
  reload: () => void;
  ensureLoaded: () => void;
}

const VIPsContext = createContext<VIPsContextValue | null>(null);

export const VIPsProvider = ({ children }: { children: ReactNode }) => {
  const { role, username, loading: authLoading } = useAuth();
  const [vips, setVips] = useState<F5VIP[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [lastLoadedAt, setLastLoadedAt] = useState<number | null>(null);
  const loadingRef = useRef(false);
  const abortRef = useRef<AbortController | null>(null);

  const reload = useCallback(() => {
    abortRef.current?.abort();
    const abortController = new AbortController();
    abortRef.current = abortController;
    loadingRef.current = true;
    setLoading(true);
    setError(null);
    setVips([]);
    let succeeded = false;
    APIService.streamVIPs(
      (batch) => {
        setVips((current) => {
          const next = new Map(current.map((vip) => [`${vip.target}:${vip.name}:${vip.ip}`, vip]));
          batch.forEach((vip) => next.set(`${vip.target}:${vip.name}:${vip.ip}`, vip));
          return Array.from(next.values()).sort((a, b) => a.name.localeCompare(b.name));
        });
        succeeded = true;
      },
      undefined,
      abortController.signal
    )
      .catch(async (e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        try {
          const list = await APIService.listVIPs();
          setVips(list);
          succeeded = true;
        } catch (fallbackError) {
          setError(fallbackError instanceof Error ? fallbackError.message : 'Failed to load VIPs');
        }
      })
      .finally(() => {
        if (abortRef.current !== abortController) return;
        loadingRef.current = false;
        setLoading(false);
        // Only mark as loaded on success — keeps ensureLoaded() retry-able if
        // the initial fetch raced auth and got 401'd.
        if (succeeded) setLastLoadedAt(Date.now());
      });
  }, []);

  const ensureLoaded = useCallback(() => {
    if (lastLoadedAt !== null) return;
    if (loadingRef.current) return;
    reload();
  }, [lastLoadedAt, reload]);

  useEffect(() => {
    if (!loading) {
      loadingRef.current = false;
    }
  }, [loading]);

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  // Invalidate cache on auth transitions so the next page mount re-fetches.
  useEffect(() => {
    if (authLoading) return;
    abortRef.current?.abort();
    setVips([]);
    setLastLoadedAt(null);
    setError(null);
    loadingRef.current = false;
  }, [role, username, authLoading]);

  return (
    <VIPsContext.Provider value={{ vips, loading, error, lastLoadedAt, reload, ensureLoaded }}>
      {children}
    </VIPsContext.Provider>
  );
};

export const useVIPs = () => {
  const ctx = useContext(VIPsContext);
  if (!ctx) throw new Error('useVIPs must be used inside <VIPsProvider>');
  return ctx;
};
