import { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import { Layout } from '@/components/Layout';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Skeleton } from '@/components/ui/skeleton';
import { useAuth } from '@/contexts/AuthContext';
import { useVIPs } from '@/contexts/VIPsContext';
import { useStatus } from '@/contexts/StatusContext';
import { APIService } from '@/services/api.service';
import { useToast } from '@/hooks/use-toast';
import { AuditEntry } from '@/types/vip';
import {
  ArrowUpRight,
  FilePlus,
  History,
  LayoutDashboard,
  PlusCircle,
  RefreshCw,
  Trash2,
  ShieldCheck,
} from 'lucide-react';

type PillTone = 'brand' | 'success' | 'warning' | 'destructive' | 'neutral';

interface SummaryPillProps {
  label: string;
  value: string | number;
  tone?: PillTone;
  to?: string;
  loading?: boolean;
}

const pillToneStyles: Record<PillTone, string> = {
  brand: 'border-brand/30 bg-brand/10 text-brand',
  success: 'border-success/30 bg-success/10 text-success',
  warning: 'border-warning/30 bg-warning/10 text-warning',
  destructive: 'border-destructive/30 bg-destructive/10 text-destructive',
  neutral: 'border-border bg-muted/40 text-muted-foreground',
};

const SummaryPill = ({ label, value, tone = 'neutral', to, loading }: SummaryPillProps) => {
  const dotClass =
    tone === 'brand'
      ? 'bg-brand'
      : tone === 'success'
        ? 'bg-success'
        : tone === 'warning'
          ? 'bg-warning'
          : tone === 'destructive'
            ? 'bg-destructive'
            : 'bg-muted-foreground/60';
  const content = (
    <span
      className={`inline-flex items-center gap-2 rounded-full border px-3.5 py-1.5 text-sm font-medium transition-colors ${pillToneStyles[tone]} ${to ? 'hover:brightness-110' : ''}`}
    >
      <span className={`inline-block h-2 w-2 rounded-full ${dotClass}`} aria-hidden="true" />
      <span className="text-foreground/80">{label}</span>
      <span className="font-semibold tabular-nums text-foreground">
        {loading ? <Skeleton className="inline-block h-4 w-6 align-middle" /> : value}
      </span>
    </span>
  );
  return to ? <Link to={to}>{content}</Link> : content;
};

interface EnvRow {
  target: string;
  name: string;
  up: number;
  down: number;
  unknown: number;
}

const auditActionLabel = (action: string): string => {
  switch (action) {
    case 'admin.login':
      return 'Admin login';
    case 'vip.create':
      return 'VIP created';
    case 'vip.request':
      return 'VIP requested';
    case 'vip.decline':
      return 'VIP declined';
    case 'cert.replace':
      return 'Cert replaced';
    case 'addport.create':
      return 'Port added';
    default:
      return action;
  }
};

const fmtRelative = (ts?: string): string => {
  if (!ts) return '';
  try {
    const d = new Date(ts);
    if (Number.isNaN(d.getTime())) return ts;
    const secs = Math.floor((Date.now() - d.getTime()) / 1000);
    if (secs < 60) return `${secs}s ago`;
    const mins = Math.floor(secs / 60);
    if (mins < 60) return `${mins}m ago`;
    const hrs = Math.floor(mins / 60);
    if (hrs < 24) return `${hrs}h ago`;
    const days = Math.floor(hrs / 24);
    return `${days}d ago`;
  } catch {
    return '';
  }
};

const Dashboard = () => {
  const { role, loading: authLoading } = useAuth();
  const isAdmin = role === 'admin';
  const { toast } = useToast();
  const { vips, loading: vipsLoading, reload: reloadVips, ensureLoaded: ensureVipsLoaded } = useVIPs();
  const {
    entries: status,
    loading: statusLoading,
    reload: reloadStatus,
    ensureLoaded: ensureStatusLoaded,
  } = useStatus();

  const [pendingCount, setPendingCount] = useState<number | null>(null);
  const [audit, setAudit] = useState<AuditEntry[]>([]);
  const [auditLoading, setAuditLoading] = useState(isAdmin);
  const [auditKey, setAuditKey] = useState(0);
  const [clearingCache, setClearingCache] = useState(false);

  // Wait for /me to resolve before touching the API. Firing while auth is
  // still in flight sends a possibly-dead token, earns a 401, and hard-nav's
  // the whole app to /admin?session_expired=1 before the user has done a thing.
  useEffect(() => {
    if (authLoading) return;
    ensureVipsLoaded();
  }, [authLoading, ensureVipsLoaded]);

  useEffect(() => {
    if (authLoading) return;
    ensureStatusLoaded();
  }, [authLoading, ensureStatusLoaded]);

  useEffect(() => {
    if (!isAdmin) return;
    let cancelled = false;
    APIService.fetchVIPRequests()
      .then((list) => {
        if (cancelled) return;
        setPendingCount(list.filter((r) => r.status === 'pending').length);
      })
      .catch(() => {
        if (!cancelled) setPendingCount(null);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, auditKey]);

  useEffect(() => {
    if (!isAdmin) {
      setAuditLoading(false);
      return;
    }
    let cancelled = false;
    setAuditLoading(true);
    APIService.listAudit({ limit: 8 })
      .then((list) => {
        if (!cancelled) setAudit(list);
      })
      .catch(() => {
        if (!cancelled) setAudit([]);
      })
      .finally(() => {
        if (!cancelled) setAuditLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [isAdmin, auditKey]);

  const totals = useMemo(() => {
    let up = 0;
    let down = 0;
    let unknown = 0;
    let membersDown = 0;
    const byEnv = new Map<string, EnvRow>();
    for (const vs of status) {
      const env = vs.target;
      const row =
        byEnv.get(env) ?? { target: env, name: vs.target_name || env.toUpperCase(), up: 0, down: 0, unknown: 0 };
      if (vs.summary === 'up') {
        up += 1;
        row.up += 1;
      } else if (vs.summary === 'down') {
        down += 1;
        row.down += 1;
      } else {
        unknown += 1;
        row.unknown += 1;
      }
      for (const m of vs.members || []) {
        if (m.state === 'down') membersDown += 1;
      }
      byEnv.set(env, row);
    }
    return { up, down, unknown, membersDown, envRows: [...byEnv.values()] };
  }, [status]);

  const envOnline = totals.envRows.filter((r) => r.up + r.down + r.unknown > 0).length;

  const onRefresh = useCallback(() => {
    reloadVips();
    reloadStatus();
    setAuditKey((k) => k + 1);
  }, [reloadVips, reloadStatus]);

  const onClearCache = useCallback(async () => {
    if (clearingCache) return;
    setClearingCache(true);
    try {
      const res = await APIService.clearServerCache();
      toast({
        title: 'Cache cleared',
        description: `${res.envs_cleared} environment(s) wiped. Refreshing...`,
      });
      reloadVips();
      reloadStatus();
      setAuditKey((k) => k + 1);
    } catch (e) {
      toast({
        title: 'Failed to clear cache',
        description: e instanceof Error ? e.message : String(e),
        variant: 'destructive',
      });
    } finally {
      setClearingCache(false);
    }
  }, [clearingCache, reloadVips, reloadStatus, toast]);

  const vipsLoadingPill = vipsLoading && vips.length === 0;
  const statusLoadingPill = statusLoading && status.length === 0;

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <section className="relative mb-8">
          <div className="absolute right-0 top-0 flex gap-2">
            {isAdmin && (
              <Button
                variant="outline"
                size="sm"
                onClick={onClearCache}
                disabled={clearingCache}
                title="Wipe the server-side disk cache and force a fresh fetch from F5"
              >
                <Trash2 className={`mr-2 h-4 w-4 ${clearingCache ? 'animate-pulse' : ''}`} />
                {clearingCache ? 'Clearing...' : 'Clear cache'}
              </Button>
            )}
            <Button variant="outline" size="sm" onClick={onRefresh}>
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
          </div>
          <div className="flex flex-col items-center text-center">
            <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-brand/15 text-brand">
              <LayoutDashboard className="h-7 w-7" />
            </div>
            <h1 className="mt-4 text-3xl font-bold tracking-tight text-foreground">Dashboard</h1>
            <p className="mt-1 max-w-xl text-sm text-muted-foreground">
              Overview of every F5 environment, pending work, and recent activity.
            </p>
            <div className="mt-5 flex flex-wrap items-center justify-center gap-2">
              <SummaryPill
                label="VIPs"
                value={vips.length}
                tone="brand"
                to="/status"
                loading={vipsLoadingPill}
              />
              <SummaryPill
                label="Healthy"
                value={totals.up}
                tone="success"
                to="/status"
                loading={statusLoadingPill}
              />
              <SummaryPill
                label="Down"
                value={totals.down + totals.membersDown}
                tone={totals.down + totals.membersDown > 0 ? 'destructive' : 'neutral'}
                to="/status"
                loading={statusLoadingPill}
              />
              {isAdmin && (
                <SummaryPill
                  label="Pending"
                  value={pendingCount ?? 0}
                  tone={(pendingCount ?? 0) > 0 ? 'warning' : 'neutral'}
                  to="/admin"
                  loading={pendingCount === null}
                />
              )}
              <SummaryPill
                label="Envs"
                value={envOnline}
                tone="neutral"
                to="/status"
                loading={statusLoadingPill}
              />
            </div>
          </div>
        </section>

        <section className="mb-6 grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card className="p-5 lg:col-span-2">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold">Environments</h2>
                <p className="text-xs text-muted-foreground">
                  Per-env health snapshot — click any card to drill in.
                </p>
              </div>
              <div className="flex flex-wrap gap-3 text-[11px] text-muted-foreground">
                <Legend swatch="bg-success" label="up" />
                <Legend swatch="bg-warning" label="unknown" />
                <Legend swatch="bg-destructive" label="down" />
              </div>
            </div>
            {statusLoading && totals.envRows.length === 0 ? (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                <Skeleton className="h-28 w-full" />
                <Skeleton className="h-28 w-full" />
                <Skeleton className="h-28 w-full" />
                <Skeleton className="h-28 w-full" />
              </div>
            ) : totals.envRows.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">
                No environment data available.
              </p>
            ) : (
              <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
                {totals.envRows.map((env) => (
                  <EnvHealthCard key={env.target} env={env} />
                ))}
              </div>
            )}
          </Card>

          <Card className="p-5">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <h2 className="text-sm font-semibold">Recent activity</h2>
                <p className="text-xs text-muted-foreground">
                  {isAdmin ? 'Audit log, newest first.' : 'Sign in as admin to see audit history.'}
                </p>
              </div>
              {isAdmin && (
                <Link
                  to="/audit"
                  className="text-xs font-medium text-brand hover:underline"
                >
                  View all
                </Link>
              )}
            </div>
            {!isAdmin ? (
              <div className="flex flex-col items-center justify-center py-10 text-center">
                <History className="mb-2 h-6 w-6 text-muted-foreground" />
                <p className="text-xs text-muted-foreground">
                  Audit log is admin-only.
                </p>
              </div>
            ) : auditLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
                <Skeleton className="h-10 w-full" />
              </div>
            ) : audit.length === 0 ? (
              <p className="py-8 text-center text-sm text-muted-foreground">No activity yet.</p>
            ) : (
              <ul className="-mx-1 max-h-80 space-y-1 overflow-y-auto pr-1 text-sm">
                {audit.map((entry) => (
                  <li
                    key={entry.id}
                    className="rounded-md px-2 py-2 transition-colors hover:bg-accent/40"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="min-w-0">
                        <div className="truncate font-medium text-foreground">
                          {auditActionLabel(entry.action)}
                        </div>
                        <div className="truncate text-xs text-muted-foreground">
                          {entry.target || 'unspecified'}
                          {entry.user && <span> · {entry.user}</span>}
                        </div>
                      </div>
                      <span className="shrink-0 text-[11px] text-muted-foreground">
                        {fmtRelative(entry.ts)}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </section>

        <section>
          <h2 className="mb-3 text-sm font-semibold text-foreground">Quick actions</h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
            <QuickAction
              to="/new-vip"
              icon={FilePlus}
              title="New VIP"
              description="Submit a new VIP request — admins push directly, anonymous users queue for approval."
            />
            <QuickAction
              to="/add-port"
              icon={PlusCircle}
              title="Add port"
              description="Add another port (new VS + pool + monitor) to an existing VIP."
            />
            <QuickAction
              to="/replace-cert"
              icon={ShieldCheck}
              title="Replace SSL cert"
              description="Rotate the certificate on an existing client-SSL profile."
            />
          </div>
        </section>
      </div>
    </Layout>
  );
};

const Legend = ({ swatch, label }: { swatch: string; label: string }) => (
  <span className="inline-flex items-center gap-1.5">
    <span className={`inline-block h-2.5 w-2.5 rounded-full ${swatch}`} />
    {label}
  </span>
);

const EnvHealthCard = ({ env }: { env: EnvRow }) => {
  const total = env.up + env.down + env.unknown;
  const upPct = total > 0 ? (env.up / total) * 100 : 0;
  const unknownPct = total > 0 ? (env.unknown / total) * 100 : 0;
  const downPct = total > 0 ? (env.down / total) * 100 : 0;
  const healthPct = total > 0 ? Math.round((env.up / total) * 100) : 0;
  const allHealthy = total > 0 && env.down === 0 && env.unknown === 0;
  const hasIssues = env.down > 0;
  const headlineTone = hasIssues
    ? 'text-destructive'
    : allHealthy
      ? 'text-success'
      : 'text-warning';
  return (
    <Link
      to={`/status`}
      className="group block rounded-lg border border-border bg-card/40 p-4 transition-colors hover:border-brand/40 hover:bg-accent/30"
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-foreground">{env.name}</div>
          <div className="mt-0.5 text-[11px] text-muted-foreground">
            {total} VIP{total === 1 ? '' : 's'}
          </div>
        </div>
        <div className={`text-xl font-bold tabular-nums ${headlineTone}`}>{healthPct}%</div>
      </div>
      <div className="mt-3 flex h-2 overflow-hidden rounded-full bg-muted">
        {upPct > 0 && (
          <div className="h-full bg-success" style={{ width: `${upPct}%` }} title={`${env.up} up`} />
        )}
        {unknownPct > 0 && (
          <div
            className="h-full bg-warning"
            style={{ width: `${unknownPct}%` }}
            title={`${env.unknown} unknown`}
          />
        )}
        {downPct > 0 && (
          <div
            className="h-full bg-destructive"
            style={{ width: `${downPct}%` }}
            title={`${env.down} down`}
          />
        )}
      </div>
      <div className="mt-2.5 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px]">
        <span className="inline-flex items-center gap-1 text-success">
          <span className="inline-block h-1.5 w-1.5 rounded-full bg-success" /> {env.up} up
        </span>
        {env.unknown > 0 && (
          <span className="inline-flex items-center gap-1 text-warning">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-warning" /> {env.unknown} unknown
          </span>
        )}
        {env.down > 0 && (
          <span className="inline-flex items-center gap-1 text-destructive">
            <span className="inline-block h-1.5 w-1.5 rounded-full bg-destructive" /> {env.down} down
          </span>
        )}
        {allHealthy && (
          <span className="text-muted-foreground">All healthy</span>
        )}
      </div>
    </Link>
  );
};

const QuickAction = ({
  to,
  icon: Icon,
  title,
  description,
}: {
  to: string;
  icon: typeof FilePlus;
  title: string;
  description: string;
}) => (
  <Link to={to} className="group">
    <Card className="h-full p-5 transition-colors hover:border-brand/40 hover:bg-accent/30">
      <div className="flex items-center justify-between">
        <div className="flex h-9 w-9 items-center justify-center rounded-md bg-brand/10 text-brand">
          <Icon className="h-5 w-5" />
        </div>
        <ArrowUpRight className="h-4 w-4 text-muted-foreground transition-transform group-hover:-translate-y-0.5 group-hover:translate-x-0.5 group-hover:text-foreground" />
      </div>
      <div className="mt-4 text-sm font-semibold text-foreground">{title}</div>
      <div className="mt-1 text-xs text-muted-foreground">{description}</div>
    </Card>
  </Link>
);

export default Dashboard;
