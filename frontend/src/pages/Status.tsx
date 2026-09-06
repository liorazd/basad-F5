import { useState, useEffect, useMemo, useRef, useCallback } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { APIService } from '@/services/api.service';
import { useStatus } from '@/contexts/StatusContext';
import { F5StatusVip, F5StatusMember, NodeHistoryEntry, PoolStats } from '@/types/vip';
import { LineChart, Line, ResponsiveContainer, YAxis, Tooltip, XAxis } from 'recharts';
import {
  Activity,
  Search,
  RefreshCw,
  Loader2,
  ChevronRight,
  ChevronDown,
  Server,
  Network,
  Route,
  Pin,
} from 'lucide-react';

type Health = 'up' | 'down' | 'unknown' | 'no-members';

const fmtTs = (ts?: string): string => {
  if (!ts) return '-';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString();
  } catch {
    return ts;
  }
};

const timeAgo = (ts?: string): string => {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return '';
    const seconds = Math.floor((Date.now() - d.getTime()) / 1000);
    if (seconds < 60) return `${seconds}s ago`;
    const minutes = Math.floor(seconds / 60);
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    if (hours < 24) return `${hours}h ago`;
    const days = Math.floor(hours / 24);
    return `${days}d ago`;
  } catch {
    return '';
  }
};

const rootOf = (vsName: string): string => vsName.replace(/-\d+-vip$/, '');

const StateDot = ({ state, size = 'md' }: { state: F5StatusMember['state']; size?: 'sm' | 'md' }) => {
  const dim = size === 'sm' ? 'h-2 w-2 ring-1' : 'h-2.5 w-2.5 ring-2';
  const base = `inline-block rounded-full ring-offset-1 ring-offset-card ${dim}`;
  const color =
    state === 'up'
      ? 'bg-success ring-success/30'
      : state === 'down'
      ? 'bg-destructive ring-destructive/30'
      : 'bg-warning ring-warning/30';
  return <span className={`${base} ${color}`} title={state} />;
};

const summaryColor = (s: Health): string => {
  if (s === 'up') return 'bg-success/10 text-success border-success/30';
  if (s === 'down') return 'bg-destructive/10 text-destructive border-destructive/30';
  if (s === 'unknown') return 'bg-warning/10 text-warning border-warning/30';
  return 'bg-muted text-muted-foreground border-border';
};

const railColor = (s: Health): string =>
  s === 'up' ? 'bg-success' : s === 'down' ? 'bg-destructive' : s === 'unknown' ? 'bg-warning' : 'bg-muted-foreground/30';

const HealthBadge = ({ summary, degraded }: { summary: Health; degraded?: boolean }) => (
  <span
    className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-xs font-medium ${summaryColor(summary)}`}
  >
    <StateDot state={summary === 'no-members' ? 'unknown' : summary} size="sm" />
    {degraded && summary === 'up' ? 'degraded' : summary}
  </span>
);

type StatTone = 'neutral' | 'up' | 'down' | 'unknown';

const StatusPill = ({
  label,
  value,
  tone,
  active,
  onClick,
}: {
  label: string;
  value: number;
  tone: StatTone;
  active?: boolean;
  onClick?: () => void;
}) => {
  const toneRing: Record<StatTone, string> = {
    neutral: 'border-border bg-muted/40 text-muted-foreground',
    up: 'border-success/30 bg-success/10 text-success',
    down: 'border-destructive/30 bg-destructive/10 text-destructive',
    unknown: 'border-warning/30 bg-warning/10 text-warning',
  };
  const dotClass: Record<StatTone, string> = {
    neutral: 'bg-muted-foreground/60',
    up: 'bg-success',
    down: 'bg-destructive',
    unknown: 'bg-warning',
  };
  const activeRing: Record<StatTone, string> = {
    neutral: 'ring-foreground/40',
    up: 'ring-success/60',
    down: 'ring-destructive/60',
    unknown: 'ring-warning/60',
  };
  return (
    <button
      type="button"
      onClick={onClick}
      className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-sm font-medium transition-colors hover:brightness-110 ${toneRing[tone]} ${active ? `ring-2 ring-offset-2 ring-offset-background ${activeRing[tone]}` : ''}`}
    >
      <span className={`inline-block h-2 w-2 rounded-full ${dotClass[tone]}`} aria-hidden="true" />
      <span className="text-foreground/80">{label}</span>
      <span className="font-semibold tabular-nums text-foreground">{value}</span>
    </button>
  );
};

const MemberHistory = ({ memberKey }: { memberKey: string }) => {
  const { toast } = useToast();
  const [entries, setEntries] = useState<NodeHistoryEntry[] | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    APIService.getNodeHistory(memberKey, 20)
      .then((r) => {
        if (!cancelled) setEntries(r);
      })
      .catch((e) => {
        if (!cancelled) {
          toast({
            title: 'Error',
            description: e instanceof Error ? e.message : 'Failed to load history',
            variant: 'destructive',
          });
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [memberKey, toast]);

  if (loading) return <p className="text-xs text-muted-foreground">Loading transitions...</p>;
  if (!entries || entries.length === 0) {
    return <p className="text-xs text-muted-foreground">No transitions recorded yet.</p>;
  }
  return (
    <ul className="space-y-1 text-xs">
      {entries.map((e, i) => (
        <li key={i} className="flex items-center gap-2 font-mono">
          <span className="text-muted-foreground">{fmtTs(e.ts)}</span>
          <span>
            <span className="rounded bg-muted px-1.5 py-0.5">{e.from}</span>
            <ChevronRight className="mx-1 inline h-3 w-3" />
            <span
              className={`rounded px-1.5 py-0.5 ${
                e.to === 'up'
                  ? 'bg-success/10 text-success'
                  : e.to === 'down'
                  ? 'bg-destructive/10 text-destructive'
                  : 'bg-warning/10 text-warning'
              }`}
            >
              {e.to}
            </span>
          </span>
        </li>
      ))}
    </ul>
  );
};

const fmtCount = (n: number): string => {
  if (n >= 1e9) return `${(n / 1e9).toFixed(1)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(1)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return String(n);
};

const StatTile = ({ label, value }: { label: string; value: string }) => (
  <div className="rounded-md border border-border bg-background px-2.5 py-1.5">
    <div className="text-[10px] uppercase tracking-wide text-muted-foreground">{label}</div>
    <div className="font-mono text-sm font-semibold tabular-nums text-foreground">{value}</div>
  </div>
);

const MAX_POINTS = 30;

// Live traffic for a single pool. Each fetch appends a sample so the chart shows
// the flow over time; packets/sec is derived from the delta between samples.
const PoolStatsPanel = ({ target, pool }: { target: string; pool: string }) => {
  const { toast } = useToast();
  const [series, setSeries] = useState<{ i: number; conns: number; pps: number }[]>([]);
  const [latest, setLatest] = useState<PoolStats | null>(null);
  const [loading, setLoading] = useState(false);
  const prevRef = useRef<{ t: number; pkts: number } | null>(null);
  const idxRef = useRef(0);

  const fetchOnce = useCallback(async () => {
    setLoading(true);
    try {
      const s = await APIService.getPoolStats(target, pool);
      setLatest(s);
      const t = Date.parse(s.ts) || Date.now();
      const pkts = s.totals.pktsIn + s.totals.pktsOut;
      let pps = 0;
      if (prevRef.current) {
        const dt = (t - prevRef.current.t) / 1000;
        if (dt > 0) pps = Math.max(0, Math.round((pkts - prevRef.current.pkts) / dt));
      }
      prevRef.current = { t, pkts };
      setSeries((cur) => [...cur, { i: idxRef.current++, conns: s.totals.curConns, pps }].slice(-MAX_POINTS));
    } catch (e) {
      toast({
        title: 'Pool stats',
        description: e instanceof Error ? e.message : 'Failed to load pool stats',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [target, pool, toast]);

  useEffect(() => {
    fetchOnce();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [target, pool]);

  const totals = latest?.totals;
  const maxConns = latest ? Math.max(1, ...latest.members.map((m) => m.curConns)) : 1;

  return (
    <div className="rounded-md border border-border bg-background p-3">
      <div className="mb-2 flex items-center justify-between">
        <div className="flex items-center gap-2 text-xs font-semibold text-foreground">
          <Activity className="h-3.5 w-3.5 text-brand" />
          Live traffic
          {latest && (
            <span className="font-normal text-muted-foreground">
              · updated {new Date(latest.ts).toLocaleTimeString()}
            </span>
          )}
        </div>
        <Button type="button" variant="outline" size="sm" className="h-7" onClick={fetchOnce} disabled={loading}>
          <RefreshCw className={`mr-1.5 h-3 w-3 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {totals && (
        <div className="mb-3 grid grid-cols-2 gap-2 sm:grid-cols-4">
          <StatTile label="Cur conns" value={fmtCount(totals.curConns)} />
          <StatTile label="Total conns" value={fmtCount(totals.totConns)} />
          <StatTile label="Pkts in/out" value={`${fmtCount(totals.pktsIn)}/${fmtCount(totals.pktsOut)}`} />
          <StatTile label="Bits in/out" value={`${fmtCount(totals.bitsIn)}/${fmtCount(totals.bitsOut)}`} />
        </div>
      )}

      <div className="h-28 w-full">
        {series.length <= 1 ? (
          <div className="flex h-full items-center justify-center text-[11px] text-muted-foreground">
            {loading ? 'Sampling…' : 'Hit Refresh to add data points and watch the flow.'}
          </div>
        ) : (
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={series} margin={{ top: 4, right: 6, left: -18, bottom: 0 }}>
              <XAxis dataKey="i" hide />
              <YAxis yAxisId="conns" width={28} tick={{ fontSize: 10 }} stroke="#6366f1" />
              <YAxis yAxisId="pps" orientation="right" hide />
              <Tooltip
                contentStyle={{ fontSize: 11, borderRadius: 6 }}
                labelFormatter={() => ''}
                formatter={(v: number, n: string) => [fmtCount(v), n === 'conns' ? 'Cur conns' : 'Pkts/s']}
              />
              <Line yAxisId="conns" type="monotone" dataKey="conns" stroke="#6366f1" strokeWidth={2} dot={false} isAnimationActive={false} />
              <Line yAxisId="pps" type="monotone" dataKey="pps" stroke="#10b981" strokeWidth={2} dot={false} isAnimationActive={false} />
            </LineChart>
          </ResponsiveContainer>
        )}
      </div>

      {latest && latest.members.length > 0 && (
        <div className="mt-3 space-y-1.5">
          {latest.members.map((m) => (
            <div key={m.name || m.ip} className="flex items-center gap-2 text-xs">
              <StateDot state={m.state} size="sm" />
              <span className="w-40 shrink-0 truncate font-mono text-muted-foreground" title={m.name}>
                {m.name || m.ip}
              </span>
              <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-brand"
                  style={{ width: `${Math.round((m.curConns / maxConns) * 100)}%` }}
                />
              </div>
              <span className="w-16 shrink-0 text-right font-mono tabular-nums text-foreground">
                {fmtCount(m.curConns)} cc
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

// One port row inside an expanded VIP: port -> pool (+ iRule condition), with
// member health that expands to per-member detail + transition history.
const PortRow = ({ row }: { row: F5StatusVip }) => {
  const [open, setOpen] = useState(false);
  const up = row.members.filter((m) => m.state === 'up').length;
  const down = row.members.filter((m) => m.state === 'down').length;
  return (
    <div className="rounded-md border border-border/70 bg-card">
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className="flex w-full items-center gap-3 px-3 py-2 text-left hover:bg-accent/20"
      >
        {open ? (
          <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
        ) : (
          <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
        )}
        <span className="flex w-16 shrink-0 items-center gap-1 font-mono text-sm font-semibold text-foreground">
          {row.port === 'default' ? (
            '*'
          ) : row.port === '' ? (
            <span className="inline-flex items-center gap-1 text-xs text-muted-foreground">
              <Route className="h-3 w-3" /> rule
            </span>
          ) : (
            `:${row.port}`
          )}
        </span>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted-foreground" title={row.pool}>
          {row.pool ? row.pool.split('/').pop() : '(no pool)'}
        </span>
        {row.condition && (
          <span className="hidden shrink-0 items-center gap-1 rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground sm:inline-flex">
            <Route className="h-3 w-3" />
            {row.condition}
          </span>
        )}
        <span className="shrink-0 text-xs tabular-nums">
          <span className="font-medium text-success">{up} up</span>
          {down > 0 && (
            <>
              <span className="mx-1 text-muted-foreground">/</span>
              <span className="font-medium text-destructive">{down} down</span>
            </>
          )}
        </span>
        <HealthBadge summary={row.summary} />
      </button>
      {open && (
        <div className="space-y-3 border-t border-border/60 px-3 py-3">
          {row.monitor && (
            <div className="text-[11px] text-muted-foreground">
              Monitor: <span className="font-mono">{row.monitor.split('/').pop()}</span>
            </div>
          )}
          {row.pool && <PoolStatsPanel target={row.target} pool={row.pool} />}
          {row.members.length === 0 ? (
            <p className="text-xs text-muted-foreground">No members on this pool.</p>
          ) : (
            <div className="space-y-2">
              {row.members.map((m) => {
                const displayName = m.name || (m.ip ? `${m.ip}${m.port ? ':' + m.port : ''}` : '(unnamed member)');
                const showIp = m.ip && !displayName.includes(m.ip);
                return (
                  <div key={m.key || m.name || m.ip} className="rounded-md border border-border bg-background p-2.5">
                    <div className="flex items-center justify-between gap-3">
                      <div className="flex min-w-0 items-center gap-2.5">
                        <StateDot state={m.state} />
                        <div className="min-w-0">
                          <div className="flex flex-wrap items-center gap-2">
                            <Server className="h-3 w-3 text-muted-foreground" />
                            <span className="break-all font-mono text-sm text-foreground">{displayName}</span>
                            {showIp && (
                              <span className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px] text-muted-foreground">
                                {m.ip}
                                {m.port ? ':' + m.port : ''}
                              </span>
                            )}
                          </div>
                          <div className="mt-1 text-[11px] text-muted-foreground">
                            {m.state} since <span className="font-mono">{fmtTs(m.since)}</span>{' '}
                            {m.since && <span>({timeAgo(m.since)})</span>}
                            {m.reason && (
                              <>
                                <span className="mx-1.5">-</span>
                                <span>{m.reason}</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-[10px]">
                        {m.enabled}
                      </Badge>
                    </div>
                    {m.key && (
                      <details className="mt-2">
                        <summary className="cursor-pointer text-[11px] text-muted-foreground hover:text-foreground">
                          Show recent transitions
                        </summary>
                        <div className="mt-2 pl-3">
                          <MemberHistory memberKey={m.key} />
                        </div>
                      </details>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

interface VipGroup {
  key: string;
  name: string;
  ip: string;
  target: string;
  targetName: string;
  isIrule: boolean;
  persist: string;
  rows: F5StatusVip[];
  summary: Health;
  degraded: boolean;
  up: number;
  down: number;
}

const Status = () => {
  const { toast } = useToast();
  const { entries, loading, loadingNote, error, reload, ensureLoaded } = useStatus();
  const [search, setSearch] = useState('');
  const [stateFilter, setStateFilter] = useState<'all' | 'up' | 'down' | 'unknown'>('all');
  const [targetFilter, setTargetFilter] = useState<string>('all');
  const [openVips, setOpenVips] = useState<Set<string>>(new Set());

  useEffect(() => {
    ensureLoaded();
  }, [ensureLoaded]);

  useEffect(() => {
    if (error) {
      toast({ title: 'Error', description: error, variant: 'destructive' });
    }
  }, [error, toast]);

  const toggleVip = (key: string) =>
    setOpenVips((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  // Collapse the flat status rows (one per port/pool) into one card per VIP,
  // keyed by environment + IP. iRule VIPs naturally fold their many port rows
  // back under a single card here.
  const groups = useMemo<VipGroup[]>(() => {
    const map = new Map<string, VipGroup>();
    for (const e of entries) {
      const key = `${e.target}:${e.ip}`;
      let g = map.get(key);
      if (!g) {
        g = {
          key,
          name: rootOf(e.vsName),
          ip: e.ip,
          target: e.target,
          targetName: e.target_name || e.target.toUpperCase(),
          isIrule: false,
          persist: '',
          rows: [],
          summary: 'no-members',
          degraded: false,
          up: 0,
          down: 0,
        };
        map.set(key, g);
      }
      g.rows.push(e);
      if (e.mode === 'irule') g.isIrule = true;
      if (e.persist && !g.persist) g.persist = e.persist;
    }
    for (const g of map.values()) {
      g.rows.sort((a, b) => {
        if (a.port === 'default') return 1;
        if (b.port === 'default') return -1;
        return Number(a.port) - Number(b.port);
      });
      const summaries = new Set(g.rows.map((r) => r.summary));
      g.summary = summaries.has('down')
        ? 'down'
        : summaries.has('up')
        ? 'up'
        : summaries.has('unknown')
        ? 'unknown'
        : 'no-members';
      g.degraded = g.summary === 'up' && g.rows.some((r) => r.summary === 'down');
      g.up = g.rows.reduce((n, r) => n + r.members.filter((m) => m.state === 'up').length, 0);
      g.down = g.rows.reduce((n, r) => n + r.members.filter((m) => m.state === 'down').length, 0);
    }
    return Array.from(map.values()).sort((a, b) => a.name.localeCompare(b.name));
  }, [entries]);

  const targets = useMemo(() => {
    const m = new Map<string, string>();
    for (const g of groups) m.set(g.target, g.targetName);
    return Array.from(m.entries()).map(([id, name]) => ({ id, name }));
  }, [groups]);

  const countsByTarget = useMemo(() => {
    const c: Record<string, number> = {};
    for (const g of groups) c[g.target] = (c[g.target] || 0) + 1;
    return c;
  }, [groups]);

  const counts = useMemo(() => {
    const c = { all: groups.length, up: 0, down: 0, unknown: 0 } as Record<'all' | 'up' | 'down' | 'unknown', number>;
    groups.forEach((g) => {
      if (g.summary === 'up') c.up++;
      else if (g.summary === 'down') c.down++;
      else if (g.summary === 'unknown') c.unknown++;
    });
    return c;
  }, [groups]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return groups.filter((g) => {
      if (stateFilter !== 'all' && g.summary !== stateFilter) return false;
      if (targetFilter !== 'all' && g.target !== targetFilter) return false;
      if (!q) return true;
      if (
        g.name.toLowerCase().includes(q) ||
        g.ip.includes(q) ||
        g.targetName.toLowerCase().includes(q) ||
        g.summary.includes(q)
      )
        return true;
      return g.rows.some(
        (r) =>
          r.port.includes(q) ||
          r.pool.toLowerCase().includes(q) ||
          r.monitor.toLowerCase().includes(q) ||
          (r.condition || '').toLowerCase().includes(q) ||
          r.members.some(
            (m) =>
              (m.name || '').toLowerCase().includes(q) ||
              (m.ip || '').toLowerCase().includes(q) ||
              (m.state || '').toLowerCase().includes(q),
          ),
      );
    });
  }, [groups, search, stateFilter, targetFilter]);

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <section className="relative mb-8">
          <div className="absolute right-0 top-0 z-20">
            <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
              <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
              Refresh
            </Button>
          </div>
          {/* pointer-events-none so the full-width centered block can't sit on top
              of the absolutely-positioned Refresh button and swallow its clicks;
              interactive children re-enable pointer events. */}
          <div className="pointer-events-none flex flex-col items-center text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand/15 text-brand">
              <Activity className="h-7 w-7" />
            </div>
            <h1 className="mt-4 text-3xl font-bold tracking-tight text-foreground">VIP Status</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              One card per VIP. Expand to see each port, the pool it maps to (including iRule dispatch), and
              live member health.
            </p>
            <div className="pointer-events-auto mt-5 flex flex-wrap items-center justify-center gap-2">
              <StatusPill label="VIPs" value={counts.all} tone="neutral" active={stateFilter === 'all'} onClick={() => setStateFilter('all')} />
              <StatusPill label="Up" value={counts.up} tone="up" active={stateFilter === 'up'} onClick={() => setStateFilter('up')} />
              <StatusPill label="Down" value={counts.down} tone="down" active={stateFilter === 'down'} onClick={() => setStateFilter('down')} />
              <StatusPill label="Unknown" value={counts.unknown} tone="unknown" active={stateFilter === 'unknown'} onClick={() => setStateFilter('unknown')} />
            </div>
          </div>
        </section>

        <div className="mb-4 flex flex-col gap-3 rounded-lg border border-border bg-card/60 p-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap items-center gap-1">
            <span className="mr-2 text-[11px] uppercase tracking-wide text-muted-foreground">Env</span>
            <Button size="sm" variant={targetFilter === 'all' ? 'default' : 'outline'} onClick={() => setTargetFilter('all')}>
              All
              <span className="ml-1.5 text-xs opacity-70">{groups.length}</span>
            </Button>
            {targets.map((t) => (
              <Button key={t.id} size="sm" variant={targetFilter === t.id ? 'default' : 'outline'} onClick={() => setTargetFilter(t.id)}>
                {t.name}
                <span className="ml-1.5 text-xs opacity-70">{countsByTarget[t.id] || 0}</span>
              </Button>
            ))}
          </div>
          <div className="relative w-full sm:w-80">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search VIP, IP, pool, port, member, state..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-9 pl-8"
            />
          </div>
        </div>

        {loading && (
          <div className="mb-3 flex items-center gap-2 rounded-md border border-border bg-muted/40 px-4 py-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin text-primary" />
            <span>{loadingNote || `Loaded ${groups.length} VIPs. Loading more...`}</span>
          </div>
        )}

        {loading && filtered.length === 0 ? (
          <Card className="p-8 text-center">
            <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
            <p className="mt-2 text-sm text-muted-foreground">{loadingNote || 'Loading status from F5...'}</p>
          </Card>
        ) : filtered.length === 0 ? (
          <Card className="p-8 text-center text-sm text-muted-foreground">
            {groups.length === 0 ? 'No VIPs found.' : 'No VIPs match your filters.'}
          </Card>
        ) : (
          <div className="space-y-2.5">
            {filtered.map((g) => {
              const isOpen = openVips.has(g.key);
              const portCount = g.rows.filter((r) => r.port !== 'default').length;
              return (
                <Card key={g.key} className="overflow-hidden p-0">
                  <button
                    type="button"
                    onClick={() => toggleVip(g.key)}
                    className={`flex w-full items-center gap-3 px-3 py-3 text-left transition-colors ${isOpen ? 'bg-accent/30' : 'hover:bg-accent/20'}`}
                  >
                    <span className={`h-9 w-1.5 shrink-0 rounded-full ${railColor(g.summary)}`} aria-hidden="true" />
                    {isOpen ? (
                      <ChevronDown className="h-4 w-4 shrink-0 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 shrink-0 text-muted-foreground" />
                    )}
                    <div className="min-w-0 flex-1">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="break-all font-semibold text-foreground">{g.name}</span>
                        {g.isIrule && (
                          <Badge variant="outline" className="gap-1 text-[10px]">
                            <Route className="h-3 w-3" /> iRule
                          </Badge>
                        )}
                        {g.persist && (
                          <Badge
                            variant="outline"
                            className="gap-1 text-[10px]"
                            title={`Persistence: ${g.persist}`}
                          >
                            <Pin className="h-3 w-3" /> {g.persist}
                          </Badge>
                        )}
                      </div>
                      <div className="mt-0.5 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted-foreground">
                        <span className="inline-flex items-center gap-1 font-mono">
                          <Network className="h-3 w-3" />
                          {g.ip}
                        </span>
                        <span>·</span>
                        <Badge variant="secondary" className="text-[10px]">
                          {g.targetName}
                        </Badge>
                        <span>·</span>
                        <span>{portCount} port{portCount === 1 ? '' : 's'}</span>
                      </div>
                    </div>
                    <div className="hidden shrink-0 text-right text-xs tabular-nums sm:block">
                      <span className="font-medium text-success">{g.up} up</span>
                      {g.down > 0 && (
                        <>
                          <span className="mx-1 text-muted-foreground">/</span>
                          <span className="font-medium text-destructive">{g.down} down</span>
                        </>
                      )}
                    </div>
                    <HealthBadge summary={g.summary} degraded={g.degraded} />
                  </button>
                  {isOpen && (
                    <div className="space-y-2 border-t border-border/60 bg-muted/10 p-3">
                      {g.rows.map((r) => (
                        <PortRow key={`${r.vsName}:${r.port}:${r.pool}`} row={r} />
                      ))}
                    </div>
                  )}
                </Card>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
};

export default Status;
