import { useState, useMemo, useEffect } from 'react';
import { Layout } from '@/components/Layout';
import { VIPPicker } from '@/components/VIPPicker';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { APIService } from '@/services/api.service';
import { F5Environment, F5VIP, PoolMember, IRuleVersion } from '@/types/vip';
import { useAuth } from '@/contexts/AuthContext';
import { PlusCircle, Plus, Trash2, ChevronLeft, History, RotateCcw } from 'lucide-react';

const stripSpaces = (v: string) => v.replace(/\s+/g, '');
const validIp = (ip: string) =>
  /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(ip);
const validPort = (p: string) => {
  const n = parseInt(p, 10);
  return !isNaN(n) && n > 0 && n <= 65535;
};
const targetLabel = (vip: F5VIP) => vip.target_name || vip.target.toUpperCase();

const ipv4ToInt = (ip: string): number => {
  const parts = ip.split('.').map((p) => Number(p));
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) return NaN;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
};
const ipInCidr = (ip: string, cidr: string): boolean => {
  const [base, maskStr] = cidr.split('/');
  const mask = parseInt(maskStr, 10);
  const ipInt = ipv4ToInt(ip);
  const baseInt = ipv4ToInt(base);
  if (isNaN(ipInt) || isNaN(baseInt) || isNaN(mask)) return false;
  const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (ipInt & maskInt) === (baseInt & maskInt);
};
const intToIpv4 = (n: number): string =>
  [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join('.');
const cidrNetworkInt = (cidr: string): number => {
  const [base, maskStr] = cidr.split('/');
  const mask = parseInt(maskStr, 10);
  const baseInt = ipv4ToInt(base);
  if (isNaN(baseInt) || isNaN(mask)) return NaN;
  const maskInt = mask === 0 ? 0 : (~0 << (32 - mask)) >>> 0;
  return (baseInt & maskInt) >>> 0;
};
// Mirror the backend's resolve_snat_ip: fixed snat_ip, or host-preserving remap
// onto snat_network (172.20.63.157 -> 172.20.7.157). null => the backend picks
// a free address in the range, or automap once it's full — it can't be
// predicted here because only the device knows which addresses are taken.
const resolveSnatIp = (vip: F5VIP | null, envs: F5Environment[]): string | null => {
  if (!vip) return null;
  const env = envs.find((e) => e.id === vip.target);
  if (!env || !env.snat_mappings) return null;
  for (const m of env.snat_mappings) {
    if (!ipInCidr(vip.ip, m.vip_cidr)) continue;
    if (m.snat_ip) return m.snat_ip;
    if (m.snat_network) {
      const host = (ipv4ToInt(vip.ip) - cidrNetworkInt(m.vip_cidr)) >>> 0;
      const snatIp = intToIpv4((cidrNetworkInt(m.snat_network) + host) >>> 0);
      // The mirrored host only exists if the SNAT range is big enough to hold it.
      return ipInCidr(snatIp, m.snat_network) ? snatIp : null;
    }
  }
  return null;
};
// True when a mapping covers this VIP but its host octet doesn't fit the SNAT
// range — the backend will allocate the next free address instead.
const hasSnatMapping = (vip: F5VIP | null, envs: F5Environment[]): boolean => {
  if (!vip) return false;
  const env = envs.find((e) => e.id === vip.target);
  return Boolean(env?.snat_mappings?.some((m) => ipInCidr(vip.ip, m.vip_cidr)));
};

const AddPort = () => {
  const { toast } = useToast();
  const { role, email } = useAuth();
  const [selectedVip, setSelectedVip] = useState<F5VIP | null>(null);
  const [newPort, setNewPort] = useState('');
  const [requesterEmail, setRequesterEmail] = useState(email || '');
  const [poolMembers, setPoolMembers] = useState<PoolMember[]>([
    { id: '1', ipAddress: '', port: '' },
  ]);
  const [sslEnabled, setSslEnabled] = useState(false);
  const [clientSslProfile, setClientSslProfile] = useState('');
  const [monitorUri, setMonitorUri] = useState('/');
  const [monitorRecv, setMonitorRecv] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [iruleVersions, setIruleVersions] = useState<IRuleVersion[]>([]);
  const [activeVersion, setActiveVersion] = useState<number | null>(null);
  const [loadingVersions, setLoadingVersions] = useState(false);
  const [rollingBack, setRollingBack] = useState<number | null>(null);
  const isAdminDirect = role === 'admin' && Boolean(APIService.getAdminToken());
  const isIruleVip = selectedVip?.mode === 'irule';

  const loadIruleVersions = async (vip: F5VIP) => {
    if (!isAdminDirect || vip.mode !== 'irule') return;
    setLoadingVersions(true);
    try {
      const res = await APIService.getIRuleVersions(vip.target, vip.name, vip.ip);
      setIruleVersions(res.versions || []);
      setActiveVersion(res.active_version);
    } catch (e: unknown) {
      const err = e as { message?: string };
      toast({ title: 'Could not load iRule versions', description: err?.message, variant: 'destructive' });
    } finally {
      setLoadingVersions(false);
    }
  };

  const handleRollback = async (toVersion: number) => {
    if (!selectedVip) return;
    setRollingBack(toVersion);
    try {
      const res = await APIService.rollbackIRule({
        vip_name: selectedVip.name,
        vip_ip: selectedVip.ip,
        target: selectedVip.target,
        to_version: toVersion,
      });
      setActiveVersion(res.active_version);
      toast({ title: 'Rolled back', description: `${selectedVip.name} now uses ${res.irule_name}` });
    } catch (e: unknown) {
      const err = e as { message?: string };
      toast({ title: 'Rollback failed', description: err?.message, variant: 'destructive' });
    } finally {
      setRollingBack(null);
    }
  };

  useEffect(() => {
    if (selectedVip && selectedVip.mode === 'irule' && isAdminDirect) {
      loadIruleVersions(selectedVip);
    } else {
      setIruleVersions([]);
      setActiveVersion(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedVip, isAdminDirect]);

  const activeEnvs = useMemo(() => APIService.getActiveEnvironments(), []);
  const snatPreview = useMemo(
    () => resolveSnatIp(selectedVip, activeEnvs),
    [selectedVip, activeEnvs],
  );
  const snatMapped = useMemo(
    () => hasSnatMapping(selectedVip, activeEnvs),
    [selectedVip, activeEnvs],
  );

  useEffect(() => {
    if (email && !requesterEmail) setRequesterEmail(email);
  }, [email, requesterEmail]);

  const availableSslProfiles = useMemo(() => {
    if (!selectedVip) return [];
    const set = new Set<string>();
    selectedVip.ports.forEach((p) => {
      (p.profiles || []).forEach((prof) => {
        const lower = prof.toLowerCase();
        if (lower.includes('client-ssl') || lower.includes('clientssl')) {
          set.add(prof);
        }
      });
    });
    return Array.from(set);
  }, [selectedVip]);

  const handleSelectVip = (vip: F5VIP) => {
    setSelectedVip(vip);
    setNewPort('');
    setPoolMembers([{ id: '1', ipAddress: '', port: '' }]);
    setSslEnabled(false);
    setClientSslProfile('');
    setMonitorUri('/');
    setMonitorRecv('');
    // Scroll to form
    setTimeout(() => {
      document.getElementById('add-port-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  };

  const addPoolMember = () => {
    setPoolMembers([...poolMembers, { id: Date.now().toString(), ipAddress: '', port: '' }]);
  };
  const removePoolMember = (id: string) => {
    setPoolMembers(poolMembers.filter((pm) => pm.id !== id));
  };
  const updatePoolMember = (id: string, field: 'ipAddress' | 'port', value: string) => {
    setPoolMembers(
      poolMembers.map((pm) => (pm.id === id ? { ...pm, [field]: stripSpaces(value) } : pm))
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedVip) {
      toast({ title: 'Error', description: 'Pick a VIP first', variant: 'destructive' });
      return;
    }
    if (!validPort(newPort)) {
      toast({ title: 'Error', description: 'Enter a valid port (1-65535)', variant: 'destructive' });
      return;
    }
    if (selectedVip.ports.some((p) => p.port === newPort.toString())) {
      toast({
        title: 'Error',
        description: `Port ${newPort} already exists on this VIP`,
        variant: 'destructive',
      });
      return;
    }
    for (const pm of poolMembers) {
      if (!validIp(pm.ipAddress)) {
        toast({
          title: 'Error',
          description: `Invalid IP: ${pm.ipAddress || '(empty)'}`,
          variant: 'destructive',
        });
        return;
      }
    }
    if (sslEnabled && !clientSslProfile) {
      toast({
        title: 'Error',
        description: 'Pick a client-SSL profile (or disable SSL)',
        variant: 'destructive',
      });
      return;
    }
    if (!isAdminDirect && !requesterEmail.trim()) {
      toast({
        title: 'Error',
        description: 'Requester email is required',
        variant: 'destructive',
      });
      return;
    }
    const trimmedUri = monitorUri.trim();
    const trimmedRecv = monitorRecv.trim();
    if (!trimmedUri || !trimmedRecv) {
      toast({
        title: 'Error',
        description: 'Health-check URI and expected response are required',
        variant: 'destructive',
      });
      return;
    }
    const normalizedUri = trimmedUri.startsWith('/') ? trimmedUri : `/${trimmedUri}`;
    setSubmitting(true);
    try {
      if (isAdminDirect) {
        const result = await APIService.addPort({
          vip_name: selectedVip.name,
          vip_ip: selectedVip.ip,
          target: selectedVip.target,
          port: newPort,
          pool_members: poolMembers.map((pm) => ({ ip_address: pm.ipAddress })),
          ssl_enabled: sslEnabled,
          clientssl_profile: sslEnabled ? clientSslProfile : undefined,
          monitor_uri: normalizedUri,
          monitor_recv: trimmedRecv,
        });
        toast({
          title: 'Success',
          description:
            result.mode === 'irule'
              ? `Added port ${newPort} to ${selectedVip.name} via ${result.irule_name} (v${result.irule_version})`
              : `Created ${result.vs_name} on ${selectedVip.ip}:${newPort}`,
        });
        if (result.mode === 'irule') loadIruleVersions(selectedVip);
      } else {
        await APIService.createAddPortRequest({
          vip_name: selectedVip.name,
          vip_ip: selectedVip.ip,
          target: selectedVip.target,
          port: newPort,
          email: requesterEmail.trim(),
          pool_members: poolMembers.map((pm) => ({ ip_address: pm.ipAddress })),
          ssl_enabled: sslEnabled,
          clientssl_profile: sslEnabled ? clientSslProfile : undefined,
          monitor_uri: normalizedUri,
          monitor_recv: trimmedRecv,
        });
        toast({
          title: 'Request submitted',
          description: `Add-port request for ${selectedVip.ip}:${newPort} is waiting for admin approval.`,
        });
      }
      setNewPort('');
      setPoolMembers([{ id: '1', ipAddress: '', port: '' }]);
      setSslEnabled(false);
      setClientSslProfile('');
      setMonitorUri('/');
      setMonitorRecv('');
    } catch (e: unknown) {
      const err = e as { message?: string; code?: string };
      toast({
        title: 'Error',
        description: err?.message || 'Failed to add port',
        variant: 'destructive',
      });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-6">
          <h1 className="flex items-center gap-2 text-2xl font-bold text-foreground">
            <PlusCircle className="h-6 w-6 text-brand" /> Add Port to Existing VIP
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Pick a VIP below to request a new virtual server on the same IP.
            {isAdminDirect ? ' As admin, this will be applied directly.' : ' An admin must approve before F5 is changed.'}
          </p>
        </div>

        <section className="mb-8">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            1. Pick a VIP
          </h2>
          <VIPPicker selectedVip={selectedVip} onSelect={handleSelectVip} />
        </section>

        {selectedVip && (
          <section id="add-port-form" className="scroll-mt-4">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                2. Configure the new port
              </h2>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setSelectedVip(null)}
              >
                <ChevronLeft className="mr-1 h-4 w-4" /> Pick a different VIP
              </Button>
            </div>

            <Card className="p-6">
              <form onSubmit={handleSubmit} className="space-y-5">
                <div className="rounded-md border border-border bg-muted/30 p-3 text-sm">
                  <div className="break-all font-semibold text-foreground">{selectedVip.name}</div>
                  <div className="mt-1 text-xs text-muted-foreground">
                    <span className="font-mono">{selectedVip.ip}</span>
                    <span className="mx-2">·</span>
                    <Badge variant="outline">{targetLabel(selectedVip)}</Badge>
                    <span className="mx-2">·</span>
                    <span>existing ports:</span>
                  </div>
                  <div className="mt-2 flex flex-wrap gap-1">
                    {selectedVip.ports.map((p) => (
                      <span
                        key={p.vsName}
                        className="rounded bg-muted px-2 py-0.5 font-mono text-xs"
                      >
                        {p.port}
                      </span>
                    ))}
                  </div>
                  {activeEnvs.length > 0 && (
                    <div className="mt-3 text-xs">
                      {snatPreview ? (
                        <span className="text-muted-foreground">
                          SNAT: <span className="font-mono text-foreground">{snatPreview}</span>
                        </span>
                      ) : snatMapped ? (
                        <span className="text-muted-foreground">
                          The SNAT range mapped to {selectedVip.ip} is too small to keep its host octet — the next free address in that range is used, or <span className="font-mono text-foreground">automap</span> if the range is full.
                        </span>
                      ) : (
                        <span className="text-muted-foreground">
                          No SNAT mapping covers {selectedVip.ip} — this port will use <span className="font-mono text-foreground">automap</span>.
                        </span>
                      )}
                    </div>
                  )}
                  <div className="mt-2 text-xs">
                    {selectedVip.mode === 'irule' ? (
                      <span className="text-muted-foreground">
                        This VIP dispatches ports via a switch iRule. The new port&apos;s pool will be
                        added as a new iRule version (rollback stays available).
                      </span>
                    ) : (
                      <span className="text-muted-foreground">
                        A new virtual server <span className="font-mono text-foreground">{selectedVip.name}-{newPort || '__'}-vip</span> will be created.
                      </span>
                    )}
                  </div>
                </div>

                <div className="grid gap-5 md:grid-cols-2">
                  {!isAdminDirect && (
                    <div className="space-y-2 md:col-span-2">
                      <Label htmlFor="requesterEmail">Requester Email *</Label>
                      <Input
                        id="requesterEmail"
                        type="email"
                        value={requesterEmail}
                        onChange={(e) => setRequesterEmail(stripSpaces(e.target.value))}
                        placeholder="your.email@example.org"
                        required
                      />
                    </div>
                  )}
                  <div className="space-y-2">
                    <Label htmlFor="newPort">New Port *</Label>
                    <Input
                      id="newPort"
                      inputMode="numeric"
                      value={newPort}
                      onChange={(e) => setNewPort(e.target.value.replace(/\D/g, ''))}
                      placeholder="e.g. 8443"
                      required
                    />
                  </div>
                  <div className="flex items-center gap-2 md:mt-7">
                    <Checkbox
                      id="ssl"
                      checked={sslEnabled}
                      onCheckedChange={(c) => setSslEnabled(c as boolean)}
                    />
                    <Label htmlFor="ssl" className="cursor-pointer">
                      Enable SSL on this port
                    </Label>
                  </div>
                </div>

                {sslEnabled && (
                  <div className="space-y-2">
                    <Label htmlFor="sslProfile">Reuse existing client-SSL profile</Label>
                    {availableSslProfiles.length > 0 ? (
                      <select
                        id="sslProfile"
                        value={clientSslProfile}
                        onChange={(e) => setClientSslProfile(e.target.value)}
                        className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                      >
                        <option value="">-- pick a profile --</option>
                        {availableSslProfiles.map((p) => (
                          <option key={p} value={p}>
                            {p}
                          </option>
                        ))}
                      </select>
                    ) : (
                      <p className="text-xs text-muted-foreground">
                        No client-SSL profiles on this VIP. To add SSL to a brand-new port,
                        use the New VIP page, or upload a cert via Replace SSL Cert first.
                      </p>
                    )}
                  </div>
                )}

                <div className="rounded-md border border-border bg-card/40 p-4 space-y-3">
                  <div>
                    <Label className="text-sm font-semibold">HTTPS Health Check *</Label>
                    <p className="mt-1 text-xs text-muted-foreground">
                      The new pool needs a real HTTPS probe. URI is hit on each member; the response must contain the expected text.
                    </p>
                  </div>
                  <div className="grid gap-3 sm:grid-cols-2">
                    <div className="space-y-1">
                      <Label htmlFor="monitorUri" className="text-xs">Health URI *</Label>
                      <Input
                        id="monitorUri"
                        value={monitorUri}
                        onChange={(e) => setMonitorUri(stripSpaces(e.target.value))}
                        placeholder="/health"
                        required
                      />
                    </div>
                    <div className="space-y-1">
                      <Label htmlFor="monitorRecv" className="text-xs">Expected response *</Label>
                      <Input
                        id="monitorRecv"
                        value={monitorRecv}
                        onChange={(e) => setMonitorRecv(e.target.value)}
                        placeholder="OK"
                        required
                      />
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Pool Members *</Label>
                  {poolMembers.map((pm) => (
                    <div key={pm.id} className="flex gap-2">
                      <Input
                        value={pm.ipAddress}
                        onChange={(e) => updatePoolMember(pm.id, 'ipAddress', e.target.value)}
                        placeholder="IP Address (e.g., 192.168.1.1)"
                        required
                      />
                      {poolMembers.length > 1 && (
                        <Button
                          type="button"
                          variant="destructive"
                          size="icon"
                          onClick={() => removePoolMember(pm.id)}
                        >
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      )}
                    </div>
                  ))}
                  <Button type="button" variant="outline" onClick={addPoolMember} className="w-full">
                    <Plus className="mr-2 h-4 w-4" /> Add Pool Member
                  </Button>
                </div>

                <Button type="submit" className="w-full" disabled={submitting}>
                  {submitting
                    ? (isAdminDirect ? 'Adding...' : 'Submitting...')
                    : `${isAdminDirect ? 'Add' : 'Request'} port ${newPort || '__'} to ${selectedVip.name}`}
                </Button>
              </form>
            </Card>

            {isIruleVip && isAdminDirect && (
              <Card className="mt-6 p-6">
                <div className="mb-3 flex items-center gap-2">
                  <History className="h-5 w-5 text-brand" />
                  <h3 className="text-sm font-semibold text-foreground">iRule versions</h3>
                </div>
                <p className="mb-4 text-xs text-muted-foreground">
                  Each port added to this VIP creates a new iRule version. Roll back to a previous
                  version to undo a change — the virtual server is re-pointed; older versions stay on the F5.
                </p>
                {loadingVersions ? (
                  <p className="text-sm text-muted-foreground">Loading versions…</p>
                ) : iruleVersions.length === 0 ? (
                  <p className="text-sm text-muted-foreground">No versioned iRules found for this VIP yet.</p>
                ) : (
                  <div className="space-y-2">
                    {iruleVersions
                      .slice()
                      .sort((a, b) => b.version - a.version)
                      .map((v) => {
                        const isActive = v.version === activeVersion;
                        return (
                          <div
                            key={v.version}
                            className="flex items-center justify-between rounded-md border border-border px-3 py-2"
                          >
                            <div className="flex items-center gap-2 text-sm">
                              <span className="font-mono">{v.name}</span>
                              {isActive && <Badge variant="outline">active</Badge>}
                            </div>
                            <Button
                              type="button"
                              variant="outline"
                              size="sm"
                              disabled={isActive || rollingBack !== null}
                              onClick={() => handleRollback(v.version)}
                            >
                              <RotateCcw className="mr-1 h-3.5 w-3.5" />
                              {rollingBack === v.version ? 'Rolling back…' : 'Roll back'}
                            </Button>
                          </div>
                        );
                      })}
                  </div>
                )}
              </Card>
            )}
          </section>
        )}
      </div>
    </Layout>
  );
};

export default AddPort;
