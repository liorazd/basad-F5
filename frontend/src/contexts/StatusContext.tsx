import { createContext, useCallback, useContext, useEffect, useRef, useState, ReactNode } from 'react';
import { F5StatusVip } from '@/types/vip';
import { APIService } from '@/services/api.service';
import { useAuth } from '@/contexts/AuthContext';

interface StatusContextValue {
  entries: F5StatusVip[];
  loading: boolean;
  loadingNote: string;
  error: string | null;
  lastLoadedAt: number | null;
  reload: () => void;
  ensureLoaded: () => void;
}

const StatusContext = createContext<StatusContextValue | null>(null);

export const StatusProvider = ({ children }: { children: ReactNode }) => {
  const { role, username, loading: authLoading } = useAuth();
  const [entries, setEntries] = useState<F5StatusVip[]>([]);
  const [loading, setLoading] = useState(false);
  const [loadingNote, setLoadingNote] = useState('');
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
    setLoadingNote('Connecting to F5...');
    setEntries([]);
    let succeeded = false;

    APIService.streamF5Status(
      (batch) => {
        setEntries((current) => {
          // Key by VS + port + pool: an iRule VIP emits several rows that share
          // a vsName (one per dispatched port), so keying on vsName alone would
          // collapse them into one.
          const keyOf = (e: F5StatusVip) => `${e.target}:${e.vsName}:${e.port}:${e.pool}`;
          const next = new Map(current.map((entry) => [keyOf(entry), entry]));
          batch.forEach((entry) => next.set(keyOf(entry), entry));
          return Array.from(next.values()).sort((a, b) => a.vsName.localeCompare(b.vsName));
        });
      },
      undefined,
      (event) => {
        if (event.event === 'start') {
          setLoadingNote(`Loading ${event.environments || 0} environment(s)...`);
        } else if (event.event === 'environment') {
          setLoadingNote(
            `Reading ${event.target_name || event.target}: ${event.virtuals || 0} VIPs, ${event.pools || 0} pools`,
          );
        } else if (event.event === 'done') {
          succeeded = true;
          setLoadingNote('');
        }
      },
      abortController.signal,
    )
      .catch(async (e) => {
        if (e instanceof DOMException && e.name === 'AbortError') return;
        try {
          setLoadingNote('Streaming failed, loading fallback snapshot...');
          const list = await APIService.getF5Status();
          setEntries(list);
          succeeded = true;
        } catch (fallbackError) {
          setError(fallbackError instanceof Error ? fallbackError.message : 'Failed to load status');
        }
      })
      .finally(() => {
        if (abortRef.current !== abortController) return;
        loadingRef.current = false;
        setLoading(false);
        setLoadingNote('');
        // Only mark "loaded" on success — otherwise ensureLoaded() should retry
        // next mount (e.g. after auth lands and the previous 401 retry can now succeed).
        if (succeeded) setLastLoadedAt(Date.now());
      });
  }, []);

  const ensureLoaded = useCallback(() => {
    if (lastLoadedAt !== null) return;
    if (loadingRef.current) return;
    reload();
  }, [lastLoadedAt, reload]);

  useEffect(() => {
    if (!loading) loadingRef.current = false;
  }, [loading]);

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  // When the user logs in / out / changes role, drop the cache so the next
  // page mount re-fetches with the current identity.
  useEffect(() => {
    if (authLoading) return;
    abortRef.current?.abort();
    setEntries([]);
    setLastLoadedAt(null);
    setError(null);
    loadingRef.current = false;
    // Note: we intentionally don't auto-reload here. The next page that calls
    // ensureLoaded() will trigger the fetch.
  }, [role, username, authLoading]);

  return (
    <StatusContext.Provider
      value={{ entries, loading, loadingNote, error, lastLoadedAt, reload, ensureLoaded }}
    >
      {children}
    </StatusContext.Provider>
  );
};

export const useStatus = () => {
  const ctx = useContext(StatusContext);
  if (!ctx) throw new Error('useStatus must be used inside <StatusProvider>');
  return ctx;
};
