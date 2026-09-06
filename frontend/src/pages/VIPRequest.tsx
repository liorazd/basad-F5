import { useState, useEffect } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { FilePlus, Plus, Trash2 } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import { VIPRequest as VIPRequestType, PoolMember } from '@/types/vip';
import { APIService } from '@/services/api.service';

const VIPRequest = () => {
  const { toast } = useToast();
  const [vipHost, setVipHost] = useState('');
  const [vipDomain, setVipDomain] = useState('.example.org');
  const [email, setEmail] = useState('');
  const [ports, setPorts] = useState(['']);
  const [ssl, setSsl] = useState(false);
  const [requireSni, setRequireSni] = useState(false);
  const [pfxFile, setPfxFile] = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState('');
  const [monitorUri, setMonitorUri] = useState('/');
  const [monitorRecv, setMonitorRecv] = useState('');
  const [poolMembers, setPoolMembers] = useState<PoolMember[]>([
    { id: '1', ipAddress: '', port: '' },
  ]);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [uploadProgress, setUploadProgress] = useState<number | null>(null);
  const [detectedEmail, setDetectedEmail] = useState<string | null>(null);

  const stripSpaces = (value: string) => value.replace(/\s+/g, '');
  const normalizeVipHost = (value: string) => {
    let normalized = stripSpaces(value).toLowerCase();
    normalized = normalized.replace(/^https?:\/\//, '');
    normalized = normalized.split(/[\/?#]/, 1)[0];

    const knownDomains = ['.example.org', '.corp.example.org', '.internal.example.org'];
    for (const domain of knownDomains) {
      if (normalized.endsWith(domain)) {
        normalized = normalized.slice(0, -domain.length);
        break;
      }
    }

    return normalized;
  };
  const normalizePoolMembers = (members: PoolMember[]): PoolMember[] =>
    members.map((member) => ({
      ...member,
      ipAddress: stripSpaces(member.ipAddress),
      port: stripSpaces(member.port),
    }));

  useEffect(() => {
    const tryDetectFromHeaders = async () => {
      try {
        const resp = await fetch('/', { method: 'GET', credentials: 'include', cache: 'no-store' });
        const userHeader = resp.headers.get('x-authenticated-user') || resp.headers.get('X-Authenticated-User');
        if (userHeader) {
          const detected = `${userHeader}@example.org`;
          setDetectedEmail(detected);
          setEmail(detected);
          return;
        }
      } catch (e) {
        console.warn('Header detection failed:', e);
      }

      // Fallback to backend helper if header not present
      try {
        const me = await APIService.getCurrentUser();
        if (me?.email) {
          setDetectedEmail(me.email);
          setEmail(me.email);
        }
      } catch (e) {
        console.warn('Could not detect authenticated user; email will remain manual.', e);
      }
    };

    tryDetectFromHeaders();
  }, []);

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result as string;
        // result is data URL: data:application/x-pkcs12;base64,<data>
        const base64 = result.split(',')[1];
        if (!base64) {
          reject(new Error('Could not read PFX file'));
        } else {
          resolve(base64);
        }
      };
      reader.onerror = () => reject(new Error('Failed to read PFX file'));
      reader.readAsDataURL(file);
    });
  };

  const validateIPAddress = (ip: string): boolean => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(ip);
  };

  const validatePort = (port: string): boolean => {
    const portNum = parseInt(port);
    return !isNaN(portNum) && portNum > 0 && portNum <= 65535;
  };

  const addPort = () => {
    setPorts([...ports, '']);
  };

  const removePort = (index: number) => {
    setPorts(ports.filter((_, i) => i !== index));
  };

  const updatePort = (index: number, value: string) => {
    const newPorts = [...ports];
    newPorts[index] = value.replace(/\D/g, '');
    setPorts(newPorts);
  };

  const addPoolMember = () => {
    setPoolMembers([...poolMembers, { id: Date.now().toString(), ipAddress: '', port: '' }]);
  };

  const removePoolMember = (id: string) => {
    setPoolMembers(poolMembers.filter(pm => pm.id !== id));
  };

  const updatePoolMember = (id: string, field: 'ipAddress' | 'port', value: string) => {
    setPoolMembers(
      poolMembers.map(pm =>
        pm.id === id ? { ...pm, [field]: value } : pm
      )
    );
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const normalizedVipHost = normalizeVipHost(vipHost);
    const emailToUse = stripSpaces(email || detectedEmail || '');
    const validPorts = ports.map(stripSpaces).filter(Boolean);
    const normalizedPoolMembers = normalizePoolMembers(poolMembers);

    // Validation
    if (!normalizedVipHost) {
      toast({ title: 'Error', description: 'VIP name is required', variant: 'destructive' });
      return;
    }
    const fullVipName = `${normalizedVipHost}${vipDomain}`;

    if (!emailToUse || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailToUse)) {
      toast({ title: 'Error', description: 'Valid email is required', variant: 'destructive' });
      return;
    }

    if (validPorts.length === 0) {
      toast({ title: 'Error', description: 'At least one port is required', variant: 'destructive' });
      return;
    }

    for (const port of validPorts) {
      if (!validatePort(port)) {
        toast({ title: 'Error', description: `Invalid port: ${port}`, variant: 'destructive' });
        return;
      }
    }

    if (ssl && !pfxFile) {
      toast({ title: 'Error', description: 'PFX file is required when SSL is enabled', variant: 'destructive' });
      return;
    }

    if (ssl && !pfxPassword.trim()) {
      toast({ title: 'Error', description: 'PFX password is required when SSL is enabled', variant: 'destructive' });
      return;
    }

    const trimmedUri = monitorUri.trim();
    const trimmedRecv = monitorRecv.trim();
    if (!trimmedUri || !trimmedRecv) {
      toast({
        title: 'Error',
        description: 'Health-check URI and expected response are required for every VIP',
        variant: 'destructive',
      });
      return;
    }

    for (const pm of normalizedPoolMembers) {
      if (!validateIPAddress(pm.ipAddress)) {
        toast({ title: 'Error', description: `Invalid IP address: ${pm.ipAddress}`, variant: 'destructive' });
        return;
      }
    }

    const request: VIPRequestType = {
      id: Date.now().toString(),
      vipName: fullVipName,
      email: emailToUse,
      ports: validPorts,
      ssl,
      requireSni,
      pfxFile: pfxFile || undefined,
      pfxFileBase64: ssl && pfxFile ? await fileToBase64(pfxFile) : undefined,
      pfxFileName: pfxFile?.name,
      pfxFileType: pfxFile?.type || 'application/x-pkcs12',
      pfxFileSize: pfxFile?.size,
      pfxPassword: ssl ? pfxPassword : undefined,
      poolMembers: normalizedPoolMembers,
      monitorUri: trimmedUri.startsWith('/') ? trimmedUri : `/${trimmedUri}`,
      monitorRecv: trimmedRecv,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };

    setIsSubmitting(true);
    setUploadProgress(null);
    try {
      // Store request on backend for admin approval (do NOT push to F5)
      const resp = await APIService.createVIPDraft(request);

      toast({
        title: 'Success',
        description: 'VIP request stored successfully. Waiting for admin approval.',
      });

      // Reset form
      setVipHost('');
      setVipDomain('.example.org');
      setEmail('');
      setPorts(['']);
      setSsl(false);
      setRequireSni(false);
      setPfxFile(null);
      setPfxPassword('');
      setPoolMembers([{ id: '1', ipAddress: '', port: '' }]);
      setMonitorUri('/');
      setMonitorRecv('');
    } catch (error: any) {
      console.error('Submit VIP error', error);
      toast({
        title: 'Error',
        description: `Failed to submit request: ${error?.message || error}`,
        variant: 'destructive',
      });
    } finally {
      setIsSubmitting(false);
      setUploadProgress(null);
    }
  };

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <Card className="mx-auto max-w-2xl p-6">
          <h1 className="mb-6 flex items-center gap-2 text-2xl font-bold text-foreground">
            <FilePlus className="h-6 w-6 text-brand" /> VIP Request Form
          </h1>
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="vipName">VIP Name *</Label>
              <div className="flex gap-2">
                <Input
                  id="vipName"
                  value={vipHost}
                  onChange={e => setVipHost(normalizeVipHost(e.target.value))}
                  placeholder="test vip"
                  required
                />
                <select
                  value={vipDomain}
                  onChange={e => setVipDomain(e.target.value)}
                  className="w-40 rounded-md border border-input bg-background px-3 py-2 text-sm text-foreground"
                >
                  <option value=".example.org">.example.org</option>
                  <option value=".corp.example.org">.corp.example.org</option>
                  <option value=".internal.example.org">.internal.example.org</option>
                </select>
              </div>
              <p className="text-xs text-muted-foreground">Full VIP: {vipHost ? `${normalizeVipHost(vipHost)}${vipDomain}` : `your-name${vipDomain}`}</p>
            </div>

            <div className="space-y-2">
              <Label htmlFor="email">Email *</Label>
              <Input
                id="email"
                type="email"
                value={email || detectedEmail || ''}
                onChange={e => setEmail(stripSpaces(e.target.value))}
                placeholder="your.email@example.com"
                required
              />
              {detectedEmail && (
                <p className="text-xs text-muted-foreground">Detected from SSO: {detectedEmail}</p>
              )}
            </div>

            <div className="space-y-2">
              <Label>Ports *</Label>
              {ports.map((port, index) => (
                <div key={index} className="flex gap-2">
                  <Input
                    value={port}
                    onChange={e => updatePort(index, e.target.value)}
                    placeholder="Enter port number"
                    required
                  />
                  {ports.length > 1 && (
                    <Button type="button" variant="destructive" size="icon" onClick={() => removePort(index)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
              <Button type="button" variant="outline" onClick={addPort} className="w-full">
                <Plus className="mr-2 h-4 w-4" /> Add Port
              </Button>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox id="ssl" checked={ssl} onCheckedChange={(checked) => setSsl(checked as boolean)} />
              <Label htmlFor="ssl" className="cursor-pointer">Enable SSL</Label>
            </div>

            {ssl && (
              <>
                <div className="flex items-center space-x-2">
                  <Checkbox id="sni" checked={requireSni} onCheckedChange={(checked) => setRequireSni(checked as boolean)} />
                  <Label htmlFor="sni" className="cursor-pointer">Require SNI</Label>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="pfxFile">PFX File *</Label>
                  <Input
                    id="pfxFile"
                    type="file"
                    accept=".pfx,.p12"
                    onChange={e => setPfxFile(e.target.files?.[0] || null)}
                    required
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="pfxPassword">PFX Password *</Label>
                  <Input
                    id="pfxPassword"
                    type="password"
                    value={pfxPassword}
                    onChange={e => setPfxPassword(e.target.value)}
                    placeholder="Enter PFX password"
                    required
                  />
                </div>
              </>
            )}

            <div className="rounded-md border border-border bg-card/40 p-4 space-y-3">
              <div>
                <Label className="text-sm font-semibold">HTTPS Health Check *</Label>
                <p className="mt-1 text-xs text-muted-foreground">
                  Every VIP needs a real HTTPS probe. The URI is hit on each pool member; the response must contain the expected text.
                </p>
              </div>
              <div className="grid gap-3 sm:grid-cols-2">
                <div className="space-y-1">
                  <Label htmlFor="monitorUri" className="text-xs">Health URI *</Label>
                  <Input
                    id="monitorUri"
                    value={monitorUri}
                    onChange={e => setMonitorUri(stripSpaces(e.target.value))}
                    placeholder="/health"
                    required
                  />
                </div>
                <div className="space-y-1">
                  <Label htmlFor="monitorRecv" className="text-xs">Expected response *</Label>
                  <Input
                    id="monitorRecv"
                    value={monitorRecv}
                    onChange={e => setMonitorRecv(e.target.value)}
                    placeholder="OK"
                    required
                  />
                </div>
              </div>
              <p className="text-[11px] text-muted-foreground">
                Without both, the request can't be submitted.
              </p>
            </div>

            <div className="space-y-2">
              <Label>Pool Members *</Label>
              {poolMembers.map(pm => (
                <div key={pm.id} className="flex gap-2">
                  <Input
                    value={pm.ipAddress}
                    onChange={e => updatePoolMember(pm.id, 'ipAddress', stripSpaces(e.target.value))}
                    placeholder="IP Address (e.g., 192.168.1.1)"
                    required
                  />
                  {poolMembers.length > 1 && (
                    <Button type="button" variant="destructive" size="icon" onClick={() => removePoolMember(pm.id)}>
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  )}
                </div>
              ))}
              <Button type="button" variant="outline" onClick={addPoolMember} className="w-full">
                <Plus className="mr-2 h-4 w-4" /> Add Pool Member
              </Button>
            </div>

            <Button type="submit" className="w-full" disabled={isSubmitting}>
              {isSubmitting ? 'Submitting...' : 'Submit Request'}
            </Button>
              {uploadProgress !== null && (
                <div className="mt-2 text-sm">
                  Uploading PFX: {uploadProgress}%
                </div>
              )}
          </form>
        </Card>
      </div>
    </Layout>
  );
};

export default VIPRequest;
