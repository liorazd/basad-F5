import { useState, useEffect, useMemo } from 'react';
import { Layout } from '@/components/Layout';
import { VIPPicker } from '@/components/VIPPicker';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { APIService } from '@/services/api.service';
import { F5VIP, CertInfo } from '@/types/vip';
import { ShieldCheck, Upload, AlertCircle, ChevronLeft } from 'lucide-react';

const fmtDate = (iso?: string): string => {
  if (!iso) return '—';
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch {
    return iso;
  }
};

const daysUntil = (iso?: string): number | null => {
  if (!iso) return null;
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return null;
    return Math.round((d.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  } catch {
    return null;
  }
};

const vipHasSsl = (vip: F5VIP): boolean =>
  vip.ports.some((p) =>
    (p.profiles || []).some((prof) => {
      const l = prof.toLowerCase();
      return l.includes('client-ssl') || l.includes('clientssl');
    })
  );
const targetLabel = (vip: F5VIP): string => vip.target_name || vip.target.toUpperCase();

const CertInfoCard = ({
  title,
  info,
  loading,
  empty,
  highlight,
}: {
  title: string;
  info: CertInfo | null;
  loading?: boolean;
  empty?: string;
  highlight?: 'current' | 'new';
}) => {
  const days = daysUntil(info?.notAfter);
  const expiringSoon = days !== null && days >= 0 && days <= 30;
  const expired = days !== null && days < 0;
  return (
    <Card
      className={`p-4 ${
        highlight === 'new' ? 'border-brand/40 bg-brand/5' : ''
      }`}
    >
      <div className="mb-3 flex items-center gap-2">
        <ShieldCheck className="h-4 w-4 text-brand" />
        <h3 className="text-sm font-semibold">{title}</h3>
      </div>
      {loading ? (
        <p className="text-xs text-muted-foreground">Loading...</p>
      ) : !info ? (
        <p className="text-xs text-muted-foreground">{empty || 'No data'}</p>
      ) : (
        <div className="space-y-2 text-xs">
          <div>
            <div className="text-muted-foreground">Common Name</div>
            <div className="break-all font-mono text-foreground">{info.commonName || '—'}</div>
          </div>
          <div>
            <div className="text-muted-foreground">Expires</div>
            <div className="font-mono text-foreground">
              {fmtDate(info.notAfter)}
              {days !== null && (
                <Badge
                  variant={expired || expiringSoon ? 'destructive' : 'secondary'}
                  className="ml-2"
                >
                  {expired ? `expired ${-days}d ago` : `${days} days`}
                </Badge>
              )}
            </div>
          </div>
          <div>
            <div className="text-muted-foreground">Issuer</div>
            <div className="break-all font-mono text-foreground">{info.issuer || '—'}</div>
          </div>
          {info.sans && info.sans.length > 0 && (
            <div>
              <div className="text-muted-foreground">SAN</div>
              <div className="mt-1 flex flex-wrap gap-1">
                {info.sans.map((s, i) => (
                  <span
                    key={i}
                    className="rounded bg-muted px-1.5 py-0.5 font-mono text-[10px]"
                  >
                    {s}
                  </span>
                ))}
              </div>
            </div>
          )}
          {info.subject && (
            <div>
              <div className="text-muted-foreground">Subject</div>
              <div className="break-all font-mono text-foreground">{info.subject}</div>
            </div>
          )}
        </div>
      )}
    </Card>
  );
};

const ReplaceCert = () => {
  const { toast } = useToast();
  const [selectedVip, setSelectedVip] = useState<F5VIP | null>(null);

  const [selectedProfile, setSelectedProfile] = useState('');
  const [currentCert, setCurrentCert] = useState<CertInfo | null>(null);
  const [loadingCurrent, setLoadingCurrent] = useState(false);

  const [attachVs, setAttachVs] = useState('');

  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState('');
  const [newCert, setNewCert] = useState<CertInfo | null>(null);
  const [parsing, setParsing] = useState(false);
  const [submitting, setSubmitting] = useState(false);

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

  const mode: 'replace' | 'create' =
    availableSslProfiles.length > 0 ? 'replace' : 'create';

  const handleSelectVip = (vip: F5VIP) => {
    setSelectedVip(vip);
    setSelectedProfile('');
    setCurrentCert(null);
    setAttachVs('');
    setPfxFile(null);
    setPfxPassword('');
    setNewCert(null);
    setTimeout(() => {
      document.getElementById('replace-cert-form')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }, 50);
  };

  useEffect(() => {
    if (selectedVip && availableSslProfiles.length > 0) {
      setSelectedProfile(availableSslProfiles[0]);
    } else {
      setSelectedProfile('');
    }
  }, [selectedVip, availableSslProfiles]);

  useEffect(() => {
    const run = async () => {
      if (!selectedVip || !selectedProfile) {
        setCurrentCert(null);
        return;
      }
      setLoadingCurrent(true);
      setCurrentCert(null);
      try {
        const info = await APIService.getCertInfo(selectedVip.target, selectedProfile);
        setCurrentCert(info);
      } catch (e) {
        toast({
          title: 'Error',
          description: e instanceof Error ? e.message : 'Failed to fetch current cert',
          variant: 'destructive',
        });
      } finally {
        setLoadingCurrent(false);
      }
    };
    run();
  }, [selectedVip, selectedProfile, toast]);

  const handleParsePfx = async () => {
    if (!pfxFile) {
      toast({ title: 'Error', description: 'Pick a PFX file first', variant: 'destructive' });
      return;
    }
    setParsing(true);
    try {
      const info = await APIService.parsePfx(pfxFile, pfxPassword);
      setNewCert(info);
    } catch (e) {
      toast({
        title: 'Error',
        description: e instanceof Error ? e.message : 'Failed to parse PFX',
        variant: 'destructive',
      });
    } finally {
      setParsing(false);
    }
  };

  const handleApply = async () => {
    if (!selectedVip) return;
    if (!pfxFile) {
      toast({ title: 'Error', description: 'Pick a PFX file', variant: 'destructive' });
      return;
    }
    if (mode === 'create' && !attachVs) {
      toast({
        title: 'Error',
        description: 'Pick which port (VS) to attach the new profile to',
        variant: 'destructive',
      });
      return;
    }
    setSubmitting(true);
    try {
      const result = await APIService.replaceCert({
        target: selectedVip.target,
        vip_name: selectedVip.name,
        mode,
        profile: mode === 'replace' ? selectedProfile : undefined,
        attach_vs: mode === 'create' ? attachVs : undefined,
        pfx_file: pfxFile,
        pfx_password: pfxPassword,
      });
      if (result.mode === 'replace') {
        toast({ title: 'Success', description: `Replaced cert on ${result.profile}` });
      } else {
        toast({
          title: 'Success',
          description: `Created ${result.profile} and attached to ${result.attached_to}`,
        });
      }
      if (mode === 'replace') {
        try {
          const updated = await APIService.getCertInfo(selectedVip.target, selectedProfile);
          setCurrentCert(updated);
        } catch {
          // ignore
        }
      }
      setPfxFile(null);
      setPfxPassword('');
      setNewCert(null);
    } catch (e) {
      toast({
        title: 'Error',
        description: e instanceof Error ? e.message : 'Failed to apply',
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
            <ShieldCheck className="h-6 w-6 text-brand" /> Replace SSL Certificate
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Pick a VIP below. If it has a client-SSL profile we'll replace its cert.
            If not, we'll create a new profile named <code>{'<vipname>-clientssl'}</code> and attach it to a port you pick.
          </p>
        </div>

        <section className="mb-8">
          <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-muted-foreground">
            1. Pick a VIP
          </h2>
          <VIPPicker
            selectedVip={selectedVip}
            onSelect={handleSelectVip}
            decorate={(vip) =>
              vipHasSsl(vip) ? (
                <Badge variant="secondary" className="text-[10px]">
                  <ShieldCheck className="mr-1 h-3 w-3" /> has SSL
                </Badge>
              ) : (
                <Badge variant="outline" className="text-[10px]">
                  no SSL
                </Badge>
              )
            }
          />
        </section>

        {selectedVip && (
          <section id="replace-cert-form" className="scroll-mt-4 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
                2. {mode === 'replace' ? 'Replace certificate' : 'Create new profile'}
              </h2>
              <Button variant="ghost" size="sm" onClick={() => setSelectedVip(null)}>
                <ChevronLeft className="mr-1 h-4 w-4" /> Pick a different VIP
              </Button>
            </div>

            <Card className="p-4">
              <div className="break-all font-semibold text-foreground">{selectedVip.name}</div>
              <div className="mt-1 text-xs text-muted-foreground">
                <span className="font-mono">{selectedVip.ip}</span>
                <span className="mx-2">·</span>
                <Badge variant="outline">{targetLabel(selectedVip)}</Badge>
              </div>
              <div className="mt-2 flex flex-wrap gap-1">
                {selectedVip.ports.map((p) => (
                  <span key={p.vsName} className="rounded bg-muted px-2 py-0.5 font-mono text-xs">
                    {p.port}
                  </span>
                ))}
              </div>
            </Card>

            {mode === 'replace' ? (
              <Card className="space-y-3 p-4">
                <Label htmlFor="profile">Client-SSL profile to replace</Label>
                {availableSslProfiles.length > 1 ? (
                  <select
                    id="profile"
                    value={selectedProfile}
                    onChange={(e) => setSelectedProfile(e.target.value)}
                    className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                  >
                    {availableSslProfiles.map((p) => (
                      <option key={p} value={p}>
                        {p}
                      </option>
                    ))}
                  </select>
                ) : (
                  <div className="rounded-md border border-border bg-muted/30 px-3 py-2 text-sm font-mono">
                    {selectedProfile || '—'}
                  </div>
                )}
                <p className="text-xs text-muted-foreground">
                  The cert/key on this profile will be replaced. Any VS using it picks up the new
                  cert automatically.
                </p>
              </Card>
            ) : (
              <Card className="space-y-3 p-4">
                <div className="flex items-start gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 p-3 text-sm">
                  <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-yellow-600" />
                  <div>
                    <div className="font-medium text-foreground">
                      No client-SSL profile on this VIP.
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      Upload a PFX and we'll create a profile named{' '}
                      <code className="rounded bg-muted px-1 py-0.5 font-mono">
                        {selectedVip.name}-clientssl
                      </code>{' '}
                      and attach it to the port you pick below.
                    </div>
                  </div>
                </div>
                <Label htmlFor="attachVs">Port to attach the new profile to</Label>
                <select
                  id="attachVs"
                  value={attachVs}
                  onChange={(e) => setAttachVs(e.target.value)}
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
                >
                  <option value="">-- pick a port --</option>
                  {selectedVip.ports.map((p) => (
                    <option key={p.vsName} value={p.vsName}>
                      Port {p.port} ({p.vsName})
                    </option>
                  ))}
                </select>
              </Card>
            )}

            <Card className="space-y-3 p-4">
              <div className="space-y-2">
                <Label htmlFor="pfxFile">New PFX file *</Label>
                <Input
                  id="pfxFile"
                  type="file"
                  accept=".pfx,.p12"
                  onChange={(e) => {
                    setPfxFile(e.target.files?.[0] || null);
                    setNewCert(null);
                  }}
                />
              </div>
              <div className="space-y-2">
                <Label htmlFor="pfxPassword">PFX password *</Label>
                <Input
                  id="pfxPassword"
                  type="password"
                  value={pfxPassword}
                  onChange={(e) => setPfxPassword(e.target.value)}
                  placeholder="Enter PFX password"
                />
              </div>
              <Button
                type="button"
                variant="outline"
                onClick={handleParsePfx}
                disabled={!pfxFile || parsing}
              >
                <Upload className="mr-2 h-4 w-4" />
                {parsing ? 'Parsing...' : 'Parse PFX to preview new cert'}
              </Button>
            </Card>

            <div className="grid gap-3 md:grid-cols-2">
              {mode === 'replace' ? (
                <CertInfoCard
                  title="Current certificate"
                  info={currentCert}
                  loading={loadingCurrent}
                  empty="No profile selected"
                />
              ) : (
                <CertInfoCard
                  title="Current certificate"
                  info={null}
                  empty="No existing profile on this VIP"
                />
              )}
              <CertInfoCard
                title="New certificate (from PFX)"
                info={newCert}
                empty="Upload a PFX and click Parse"
                highlight="new"
              />
            </div>

            <Button
              className="w-full"
              onClick={handleApply}
              disabled={
                submitting ||
                !pfxFile ||
                (mode === 'replace' && !selectedProfile) ||
                (mode === 'create' && !attachVs)
              }
            >
              {submitting
                ? 'Applying...'
                : mode === 'replace'
                ? 'Replace certificate on profile'
                : 'Create profile & attach to port'}
            </Button>
          </section>
        )}
      </div>
    </Layout>
  );
};

export default ReplaceCert;
