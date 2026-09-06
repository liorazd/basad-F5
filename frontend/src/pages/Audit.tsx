import { useState, useEffect, useCallback, useMemo } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { APIService } from '@/services/api.service';
import { AuditEntry } from '@/types/vip';
import { History, Search, RefreshCw, Undo2, Loader2 } from 'lucide-react';

type TypeFilter = 'all' | 'admin' | 'api' | 'requester';
const TYPE_FILTERS: TypeFilter[] = ['all', 'admin', 'api', 'requester'];

const fmtTs = (ts: string): string => {
  try {
    const d = new Date(ts);
    if (isNaN(d.getTime())) return ts;
    return d.toLocaleString();
  } catch {
    return ts;
  }
};

const Audit = () => {
  const { toast } = useToast();
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [type, setType] = useState<TypeFilter>('all');
  const [search, setSearch] = useState('');
  const [reverting, setReverting] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const items = await APIService.listAudit({
        type: type === 'all' ? undefined : type,
        search: search || undefined,
        limit: 300,
      });
      setEntries(items);
    } catch (e) {
      toast({
        title: 'Error',
        description: e instanceof Error ? e.message : 'Failed to load audit',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  }, [type, search, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const counts = useMemo(() => {
    const c = { all: entries.length, admin: 0, api: 0, requester: 0 } as Record<TypeFilter, number>;
    entries.forEach((e) => {
      if (e.user_type === 'admin') c.admin++;
      else if (e.user_type === 'api') c.api++;
      else c.requester++;
    });
    return c;
  }, [entries]);

  const handleRevert = async (entry: AuditEntry) => {
    if (!window.confirm(
      `Revert "${entry.action}" on ${entry.target}?\n\n` +
      `This will undo the F5 change. Action will be marked as reverted in the audit log.`
    )) return;
    setReverting(entry.id);
    try {
      const result = await APIService.revertAudit(entry.id);
      toast({
        title: 'Reverted',
        description: `${entry.action} on ${entry.target} undone (${result.undone?.length || 0} steps)`,
      });
      await load();
    } catch (e) {
      toast({
        title: 'Revert failed',
        description: e instanceof Error ? e.message : 'Revert failed',
        variant: 'destructive',
      });
    } finally {
      setReverting(null);
    }
  };

  const actionColor = (action: string): string => {
    if (action.startsWith('vip.approve') || action.startsWith('vip.create')) return 'bg-green-500/10 text-green-700 dark:text-green-400';
    if (action.startsWith('vip.decline')) return 'bg-red-500/10 text-red-700 dark:text-red-400';
    if (action.startsWith('cert.')) return 'bg-blue-500/10 text-blue-700 dark:text-blue-400';
    if (action.startsWith('vipport.')) return 'bg-purple-500/10 text-purple-700 dark:text-purple-400';
    if (action === 'revert') return 'bg-amber-500/10 text-amber-700 dark:text-amber-400';
    if (action.startsWith('admin.')) return 'bg-slate-500/10 text-slate-700 dark:text-slate-400';
    return 'bg-muted text-muted-foreground';
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="flex items-center gap-2 text-2xl font-bold text-foreground">
              <History className="h-6 w-6 text-brand" /> Audit Log
            </h1>
            <p className="mt-1 text-sm text-muted-foreground">
              Every mutating action against F5 is recorded here. Revertible
              entries can be undone with the Revert button.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} /> Refresh
          </Button>
        </div>

        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-1">
            {TYPE_FILTERS.map((t) => (
              <Button
                key={t}
                size="sm"
                variant={type === t ? 'default' : 'outline'}
                onClick={() => setType(t)}
              >
                {t === 'all' ? 'All' : t.charAt(0).toUpperCase() + t.slice(1)}
                <span className="ml-2 rounded-full bg-background/30 px-1.5 text-xs">
                  {counts[t]}
                </span>
              </Button>
            ))}
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              placeholder="Search actions, users, targets..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-9 pl-8"
            />
          </div>
        </div>

        <Card className="overflow-hidden p-0">
          {loading ? (
            <div className="p-8 text-center">
              <Loader2 className="mx-auto h-6 w-6 animate-spin text-primary" />
              <p className="mt-2 text-sm text-muted-foreground">Loading audit log...</p>
            </div>
          ) : entries.length === 0 ? (
            <div className="p-8 text-center text-sm text-muted-foreground">
              No audit entries yet.
            </div>
          ) : (
            <div className="max-h-[70vh] overflow-auto">
              <table className="w-full text-sm">
                <thead className="sticky top-0 z-10 border-b bg-card">
                  <tr className="text-left text-xs uppercase text-muted-foreground">
                    <th className="px-4 py-2.5 font-medium">When</th>
                    <th className="px-4 py-2.5 font-medium">User</th>
                    <th className="px-4 py-2.5 font-medium">Action</th>
                    <th className="px-4 py-2.5 font-medium">Target</th>
                    <th className="px-4 py-2.5 font-medium">Result</th>
                    <th className="px-4 py-2.5 font-medium"></th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <>
                      <tr
                        key={e.id}
                        onClick={() => setExpanded(expanded === e.id ? null : e.id)}
                        className="cursor-pointer border-b border-border/40 hover:bg-accent/30"
                      >
                        <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                          {fmtTs(e.ts)}
                        </td>
                        <td className="px-4 py-2.5">
                          <div>{e.user || '—'}</div>
                          <Badge variant="outline" className="mt-1 text-[10px]">
                            {e.user_type}
                          </Badge>
                        </td>
                        <td className="px-4 py-2.5">
                          <span className={`rounded px-2 py-0.5 text-xs font-medium ${actionColor(e.action)}`}>
                            {e.action}
                          </span>
                        </td>
                        <td className="break-all px-4 py-2.5 font-mono text-xs text-foreground">
                          {e.target || '—'}
                        </td>
                        <td className="px-4 py-2.5">
                          {e.reverted ? (
                            <Badge variant="secondary" className="text-[10px]">
                              reverted by {e.reverted_by || '?'}
                            </Badge>
                          ) : e.result === 'success' ? (
                            <Badge variant="outline" className="text-[10px]">
                              {e.result}
                            </Badge>
                          ) : (
                            <Badge variant="destructive" className="text-[10px]">
                              {e.result}
                            </Badge>
                          )}
                        </td>
                        <td className="px-4 py-2.5 text-right" onClick={(ev) => ev.stopPropagation()}>
                          {e.revertible && !e.reverted ? (
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => handleRevert(e)}
                              disabled={reverting === e.id}
                            >
                              <Undo2 className="mr-1 h-3 w-3" />
                              {reverting === e.id ? 'Reverting...' : 'Revert'}
                            </Button>
                          ) : (
                            <span className="text-[10px] text-muted-foreground">
                              {e.revertible ? '' : 'not revertible'}
                            </span>
                          )}
                        </td>
                      </tr>
                      {expanded === e.id && (
                        <tr key={e.id + '-details'} className="border-b border-border/40 bg-muted/20">
                          <td colSpan={6} className="px-4 py-3">
                            <pre className="overflow-auto rounded bg-card p-3 text-[11px] font-mono">
                              {JSON.stringify(e.details, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Card>
      </div>
    </Layout>
  );
};

export default Audit;
