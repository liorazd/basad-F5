import { useEffect, useMemo, useState, ReactNode } from 'react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { F5VIP } from '@/types/vip';
import { useVIPs } from '@/contexts/VIPsContext';
import {
  Search,
  RefreshCw,
  Loader2,
  ArrowUp,
  ArrowDown,
  ArrowUpDown,
} from 'lucide-react';

type SortKey = 'name' | 'ip' | 'target' | 'ports';
type SortDir = 'asc' | 'desc';

interface VIPPickerProps {
  selectedVip: F5VIP | null;
  onSelect: (vip: F5VIP) => void;
  decorate?: (vip: F5VIP) => ReactNode;
  filter?: (vip: F5VIP) => boolean;
  emptyHelp?: string;
}

const targetLabel = (vip: F5VIP): string => vip.target_name || vip.target.toUpperCase();

export const VIPPicker = ({
  selectedVip,
  onSelect,
  decorate,
  filter,
  emptyHelp,
}: VIPPickerProps) => {
  const { vips: allVips, loading, error, lastLoadedAt, reload, ensureLoaded } = useVIPs();

  const [search, setSearch] = useState('');
  const [targetFilter, setTargetFilter] = useState<string>('all');
  const [sortKey, setSortKey] = useState<SortKey>('name');
  const [sortDir, setSortDir] = useState<SortDir>('asc');

  useEffect(() => {
    ensureLoaded();
  }, [ensureLoaded]);

  const targets = useMemo(() => {
    const map = new Map<string, string>();
    for (const vip of allVips) {
      map.set(vip.target, targetLabel(vip));
    }
    return Array.from(map.entries()).map(([id, name]) => ({ id, name }));
  }, [allVips]);

  const countsByTarget = useMemo(() => {
    const counts: Record<string, number> = {};
    for (const vip of allVips) {
      counts[vip.target] = (counts[vip.target] || 0) + 1;
    }
    return counts;
  }, [allVips]);

  const filteredVips = useMemo(() => {
    const q = search.trim().toLowerCase();
    const filtered = allVips.filter((v) => {
      if (targetFilter !== 'all' && v.target !== targetFilter) return false;
      if (filter && !filter(v)) return false;
      if (!q) return true;
      return (
        v.name.toLowerCase().includes(q) ||
        v.ip.includes(q) ||
        targetLabel(v).toLowerCase().includes(q) ||
        v.ports.some((p) => p.port.includes(q))
      );
    });
    const cmp = (a: F5VIP, b: F5VIP): number => {
      let res = 0;
      if (sortKey === 'name') res = a.name.localeCompare(b.name);
      else if (sortKey === 'ip') {
        const aN = a.ip.split('.').map((n) => parseInt(n, 10));
        const bN = b.ip.split('.').map((n) => parseInt(n, 10));
        for (let i = 0; i < 4; i++) {
          if ((aN[i] || 0) !== (bN[i] || 0)) {
            res = (aN[i] || 0) - (bN[i] || 0);
            break;
          }
        }
      } else if (sortKey === 'target') res = targetLabel(a).localeCompare(targetLabel(b));
      else if (sortKey === 'ports') res = a.ports.length - b.ports.length;
      return sortDir === 'asc' ? res : -res;
    };
    return [...filtered].sort(cmp);
  }, [allVips, search, targetFilter, filter, sortKey, sortDir]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const SortIcon = ({ k }: { k: SortKey }) => {
    if (sortKey !== k) return <ArrowUpDown className="ml-1 inline h-3 w-3 opacity-30" />;
    return sortDir === 'asc' ? (
      <ArrowUp className="ml-1 inline h-3 w-3" />
    ) : (
      <ArrowDown className="ml-1 inline h-3 w-3" />
    );
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search by name, IP, target, or port..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="h-10 pl-9"
          />
        </div>
        <div className="flex flex-wrap gap-1">
          <Button
            size="sm"
            variant={targetFilter === 'all' ? 'default' : 'outline'}
            onClick={() => setTargetFilter('all')}
          >
            All <span className="ml-1.5 text-xs opacity-70">{allVips.length}</span>
          </Button>
          {targets.map((target) => (
            <Button
              key={target.id}
              size="sm"
              variant={targetFilter === target.id ? 'default' : 'outline'}
              onClick={() => setTargetFilter(target.id)}
            >
              {target.name} <span className="ml-1.5 text-xs opacity-70">{countsByTarget[target.id] || 0}</span>
            </Button>
          ))}
        </div>
        <Button variant="outline" size="sm" onClick={reload} disabled={loading}>
          <RefreshCw className={`mr-2 h-4 w-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {loading && (
        <Card className="p-3">
          <div className="flex items-center gap-3 text-sm">
            <Loader2 className="h-4 w-4 animate-spin text-primary" />
            <div className="flex-1">
              <div className="flex items-center justify-between">
                <span>Querying F5...</span>
                <span className="text-xs text-muted-foreground">
                  {targets.length > 0 ? `${targets.length} environment${targets.length === 1 ? '' : 's'}` : 'discovering targets'}
                </span>
              </div>
            </div>
          </div>
        </Card>
      )}

      {!loading && error && (
        <Card className="border-destructive/30 bg-destructive/5 p-3 text-xs">
          {error}
        </Card>
      )}

      <Card className="overflow-hidden p-0">
        {filteredVips.length === 0 ? (
          <div className="p-12 text-center text-sm text-muted-foreground">
            {loading
              ? 'Loading VIPs from F5...'
              : allVips.length === 0
              ? emptyHelp || 'No VIPs found.'
              : 'No VIPs match your search or filters.'}
          </div>
        ) : (
          <div className="max-h-[60vh] overflow-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10 border-b bg-card">
                <tr className="text-left text-xs uppercase text-muted-foreground">
                  <th className="cursor-pointer select-none px-4 py-2.5 font-medium hover:text-foreground" onClick={() => toggleSort('name')}>
                    Name <SortIcon k="name" />
                  </th>
                  <th className="cursor-pointer select-none px-4 py-2.5 font-medium hover:text-foreground" onClick={() => toggleSort('ip')}>
                    IP <SortIcon k="ip" />
                  </th>
                  <th className="cursor-pointer select-none px-4 py-2.5 font-medium hover:text-foreground" onClick={() => toggleSort('target')}>
                    Target <SortIcon k="target" />
                  </th>
                  <th className="cursor-pointer select-none px-4 py-2.5 font-medium hover:text-foreground" onClick={() => toggleSort('ports')}>
                    Ports <SortIcon k="ports" />
                  </th>
                  {decorate && <th className="px-4 py-2.5 font-medium">Info</th>}
                </tr>
              </thead>
              <tbody>
                {filteredVips.map((vip) => {
                  const isSelected =
                    selectedVip !== null &&
                    selectedVip.name === vip.name &&
                    selectedVip.target === vip.target &&
                    selectedVip.ip === vip.ip;
                  return (
                    <tr
                      key={`${vip.target}-${vip.name}-${vip.ip}`}
                      onClick={() => onSelect(vip)}
                      className={`cursor-pointer border-b border-border/50 transition-colors ${
                        isSelected ? 'bg-primary/10 hover:bg-primary/15' : 'hover:bg-accent/40'
                      }`}
                    >
                      <td className="break-all px-4 py-2.5 font-medium text-foreground">{vip.name}</td>
                      <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">{vip.ip}</td>
                      <td className="px-4 py-2.5">
                        <Badge variant="secondary">{targetLabel(vip)}</Badge>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="flex flex-wrap gap-1">
                          {vip.ports.map((p) => (
                            <span key={p.vsName} className="rounded bg-muted px-1.5 py-0.5 font-mono text-[11px] text-foreground">
                              {p.port}
                            </span>
                          ))}
                        </div>
                      </td>
                      {decorate && <td className="px-4 py-2.5">{decorate(vip)}</td>}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {lastLoadedAt && !loading && (
        <p className="text-right text-[11px] text-muted-foreground">
          Last loaded {new Date(lastLoadedAt).toLocaleTimeString()} · cached across pages
        </p>
      )}
    </div>
  );
};
