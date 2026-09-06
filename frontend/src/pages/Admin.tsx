import { useState, useEffect, useMemo } from 'react';
import { Layout } from '@/components/Layout';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Card } from '@/components/ui/card';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { useToast } from '@/hooks/use-toast';
import { VIPRequest, F5Environment } from '@/types/vip';
import { APIService } from '@/services/api.service';
import { useAuth } from '@/contexts/AuthContext';
import { CheckCircle, XCircle, Shield, Search, RefreshCw, Lock } from 'lucide-react';
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog';

type StatusFilter = 'all' | 'pending' | 'approved' | 'declined';
const STATUS_FILTERS: StatusFilter[] = ['all', 'pending', 'approved', 'declined'];

const formatTime = (iso: string): string => {
  try {
    const d = new Date(iso);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString();
  } catch {
    return iso;
  }
};

const Admin = () => {
  const { toast } = useToast();
  const { refresh: refreshAuth } = useAuth();
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [isCheckingAuth, setIsCheckingAuth] = useState(true);
  const [activeEnvironments, setActiveEnvironments] = useState<F5Environment[]>([]);
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('');
  const [requests, setRequests] = useState<VIPRequest[]>([]);
  const [selectedRequest, setSelectedRequest] = useState<VIPRequest | null>(null);
  const [declineReason, setDeclineReason] = useState('');
  const [showDeclineDialog, setShowDeclineDialog] = useState(false);
  const [isProcessing, setIsProcessing] = useState(false);

  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all');

  const [showRenameDialog, setShowRenameDialog] = useState(false);
  const [renameTarget, setRenameTarget] = useState<VIPRequest | null>(null);
  const [newVipName, setNewVipName] = useState('');
  const [duplicateMessage, setDuplicateMessage] = useState('');

  useEffect(() => {
    let isMounted = true;
    const checkAdminSession = async () => {
      setActiveEnvironments(APIService.getActiveEnvironments());
      const token = APIService.getAdminToken();
      if (!token) {
        if (isMounted) { setIsAuthenticated(false); setIsCheckingAuth(false); }
        return;
      }
      try {
        const items = await APIService.fetchVIPRequests();
        if (!isMounted) return;
        setRequests(items);
        setIsAuthenticated(true);
      } catch (error) {
        const message = error instanceof Error ? error.message : 'Failed to validate admin session';
        toast({ title: 'Error', description: message, variant: 'destructive' });
        if (isMounted) { setIsAuthenticated(false); setRequests([]); }
      } finally {
        if (isMounted) setIsCheckingAuth(false);
      }
    };
    checkAdminSession();
    return () => { isMounted = false; };
  }, [toast]);

  const loadRequests = async () => {
    try {
      const items = await APIService.fetchVIPRequests();
      setRequests(items);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Failed to load VIP requests';
      toast({ title: 'Error', description: message, variant: 'destructive' });
      if (message.toLowerCase().includes('unauthorized')) {
        setIsAuthenticated(false);
        setRequests([]);
      }
    }
  };

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsProcessing(true);
    try {
      const loginResult = await APIService.adminLogin(username, password);
      setIsAuthenticated(true);
      setActiveEnvironments(loginResult.environments || APIService.getActiveEnvironments());
      setPassword('');
      loadRequests();
      // Tell the global AuthContext to re-fetch the role so the sidebar
      // updates to show all admin pages.
      refreshAuth();
      const okCount = (loginResult.environments || []).filter((env) => env.authenticated).length;
      toast({ title: 'Success', description: `Logged in to ${okCount} F5 environment${okCount === 1 ? '' : 's'}` });
    } catch (error) {
      toast({ title: 'Error', description: error instanceof Error ? error.message : 'Login failed', variant: 'destructive' });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleApprove = async (request: VIPRequest, overrideName?: string) => {
    setIsProcessing(true);
    try {
      const data = await APIService.approveVIPRequest(request.id, overrideName);
      if (!data || data.success === false) throw new Error(data?.error || 'VIP creation failed');
      const assignedIP = data.ip || data.assigned_ip || '';
      await loadRequests();
      setShowRenameDialog(false);
      setRenameTarget(null);
      setNewVipName('');
      setDuplicateMessage('');
      try {
        await APIService.sendEmailNotification({
          to: request.email,
          subject: request.requestType === 'add_port' ? 'Add Port Request Approved' : 'VIP Request Approved',
          body: request.requestType === 'add_port'
            ? `Your add-port request for "${request.vipName}" has been approved. VIP IP: ${assignedIP || request.vipIP || ''}`
            : `Your VIP request "${overrideName || request.vipName}" has been approved and created. Assigned IP: ${assignedIP}`,
          type: 'success',
        });
      } catch (emailError) {
        console.warn('Email notification failed:', emailError);
      }
      toast({
        title: 'Success',
        description: request.requestType === 'add_port'
          ? `Add-port request approved for ${assignedIP || request.vipIP || request.vipName}`
          : `VIP approved. IP: ${assignedIP}`,
      });
    } catch (error: unknown) {
      const err = error as { code?: string; status?: number; message?: string };
      const isDuplicate = err?.code === 'duplicate_vip_name' || err?.status === 409;
      if (isDuplicate) {
        setRenameTarget(request);
        setNewVipName(overrideName || request.vipName);
        setDuplicateMessage(err?.message || 'A VIP with this name already exists on F5.');
        setShowRenameDialog(true);
        toast({ title: 'Duplicate VIP name', description: err?.message || 'A VIP with this name already exists. Enter a new name.', variant: 'destructive' });
      } else {
        toast({ title: 'Error', description: err?.message || 'Failed to approve VIP request. Backend may not be ready.', variant: 'destructive' });
      }
    } finally {
      setIsProcessing(false);
    }
  };

  const handleRenameApprove = () => {
    if (!renameTarget || !newVipName.trim()) return;
    handleApprove(renameTarget, newVipName.trim());
  };

  const clearAllData = () => {
    if (!window.confirm('Are you sure you want to clear all VIP requests? This will delete stored PFX files.')) return;
    setIsProcessing(true);
    APIService.clearVIPRequests()
      .then(() => { setRequests([]); toast({ title: 'Cleared', description: 'All VIP requests have been cleared.' }); })
      .catch((error) => { toast({ title: 'Error', description: error instanceof Error ? error.message : 'Failed to clear requests', variant: 'destructive' }); })
      .finally(() => setIsProcessing(false));
  };

  const handleDecline = async () => {
    if (!selectedRequest || !declineReason.trim()) {
      toast({ title: 'Error', description: 'Decline reason is required', variant: 'destructive' });
      return;
    }
    setIsProcessing(true);
    try {
      await APIService.declineVIPRequest(selectedRequest.id, declineReason);
      await loadRequests();
      try {
        await APIService.sendEmailNotification({
          to: selectedRequest.email,
          subject: 'VIP Request Declined',
          body: `Your VIP request "${selectedRequest.vipName}" has been declined. Reason: ${declineReason}`,
          type: 'declined',
        });
      } catch (emailError) {
        console.warn('Email notification failed:', emailError);
        toast({ title: 'Warning', description: 'VIP declined but email notification failed.' });
      }
      toast({ title: 'Success', description: 'VIP request declined successfully' });
      setShowDeclineDialog(false);
      setDeclineReason('');
      setSelectedRequest(null);
    } catch (error) {
      toast({ title: 'Error', description: 'Failed to decline VIP request', variant: 'destructive' });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleLogout = async () => {
    await APIService.adminLogout();
    setIsAuthenticated(false);
    setUsername('');
    setPassword('');
    setRequests([]);
    setActiveEnvironments([]);
    // Re-fetch identity so the sidebar drops admin items.
    refreshAuth();
  };

  const counts = useMemo(() => ({
    all: requests.length,
    pending: requests.filter((r) => r.status === 'pending').length,
    approved: requests.filter((r) => r.status === 'approved').length,
    declined: requests.filter((r) => r.status === 'declined').length,
  }), [requests]);

  const filteredRequests = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    const filtered = requests.filter((r) => {
      if (statusFilter !== 'all' && r.status !== statusFilter) return false;
      if (!q) return true;
      return (
        r.vipName.toLowerCase().includes(q) ||
        r.email.toLowerCase().includes(q) ||
        r.ports.some((p) => p.toLowerCase().includes(q)) ||
        r.poolMembers.some((pm) => pm.ipAddress.toLowerCase().includes(q)) ||
        (r.assignedIP || '').toLowerCase().includes(q)
      );
    });
    const rank = (s: VIPRequest['status']) => (s === 'pending' ? 0 : s === 'approved' ? 1 : 2);
    return [...filtered].sort((a, b) => {
      const sr = rank(a.status) - rank(b.status);
      if (sr !== 0) return sr;
      const at = new Date(a.createdAt).getTime();
      const bt = new Date(b.createdAt).getTime();
      return (isNaN(bt) ? 0 : bt) - (isNaN(at) ? 0 : at);
    });
  }, [requests, searchQuery, statusFilter]);

  if (isCheckingAuth) {
    return (
      <Layout>
        <div className="container mx-auto px-4 py-8">
          <Card className="mx-auto max-w-md p-6 text-center">Checking admin session...</Card>
        </div>
      </Layout>
    );
  }

  if (!isAuthenticated) {
    const sessionExpired = typeof window !== 'undefined' &&
      new URLSearchParams(window.location.search).get('session_expired') === '1';
    return (
      <Layout>
        <div className="container mx-auto px-4 py-8">
          <Card className="mx-auto max-w-md p-6">
            <div className="mb-6 flex items-center justify-center">
              <Shield className="h-12 w-12 text-brand" />
            </div>
            <h1 className="mb-2 text-center text-2xl font-bold text-foreground">Admin Login</h1>
            {sessionExpired && (
              <p className="mb-4 rounded-md border border-destructive/40 bg-destructive/10 px-3 py-2 text-center text-xs text-destructive">
                Your session expired. Please log in again.
              </p>
            )}
            <form onSubmit={handleLogin} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="username">Username</Label>
                <Input id="username" type="text" value={username} onChange={(e) => setUsername(e.target.value)} placeholder="Enter username" required />
              </div>
              <div className="space-y-2">
                <Label htmlFor="password">Password</Label>
                <Input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Enter password" required />
              </div>
              <Button type="submit" className="w-full" disabled={isProcessing}>
                {isProcessing ? 'Logging in...' : 'Login'}
              </Button>
            </form>
          </Card>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container mx-auto px-4 py-8">
        <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
          <div>
            <h1 className="text-2xl font-bold text-foreground">VIP Requests</h1>
            <p className="mt-1 text-sm text-muted-foreground">Review and approve incoming VIP requests.</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" size="sm" onClick={loadRequests} disabled={isProcessing}>
              <RefreshCw className="mr-2 h-4 w-4" /> Refresh
            </Button>
            <Button variant="destructive" size="sm" onClick={clearAllData} disabled={requests.length === 0 || isProcessing}>
              Clear All
            </Button>
            <Button variant="outline" size="sm" onClick={handleLogout}>
              <Lock className="mr-2 h-4 w-4" /> Logout
            </Button>
          </div>
        </div>

        {activeEnvironments.length > 0 && (
          <div className="mb-4 flex flex-wrap gap-x-4 gap-y-1 rounded-md border border-border bg-muted/40 px-3 py-2 text-xs text-muted-foreground">
            {activeEnvironments.map((env) => (
              <span key={env.id}>
                Active {env.name}: <span className="font-mono text-foreground">{env.url}</span>
                {env.authenticated === false && <span className="ml-1 text-destructive">(auth failed)</span>}
              </span>
            ))}
          </div>
        )}

        <div className="mb-4 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex flex-wrap gap-1">
            {STATUS_FILTERS.map((s) => (
              <Button key={s} size="sm" variant={statusFilter === s ? 'default' : 'outline'} onClick={() => setStatusFilter(s)}>
                {s.charAt(0).toUpperCase() + s.slice(1)}
                <span className="ml-2 rounded-full bg-background/30 px-1.5 text-xs">{counts[s]}</span>
              </Button>
            ))}
          </div>
          <div className="relative w-full sm:w-72">
            <Search className="pointer-events-none absolute left-2 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input placeholder="Search name, email, IP, port..." value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} className="h-9 pl-8" />
          </div>
        </div>

        {filteredRequests.length === 0 ? (
          <Card className="p-8 text-center">
            <p className="text-muted-foreground">
              {requests.length === 0 ? 'No VIP requests yet.' : 'No requests match your filters.'}
            </p>
          </Card>
        ) : (
          <div className="space-y-3">
            {filteredRequests.map((request) => (
              <Card key={request.id} className="p-4">
                <div className="flex flex-col gap-4 md:flex-row md:items-start">
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <h3 className="break-all font-semibold text-foreground">{request.vipName}</h3>
                      <Badge variant="outline">
                        {request.requestType === 'add_port' ? 'Add Port' : 'New VIP'}
                      </Badge>
                      <Badge variant={request.status === 'approved' ? 'default' : request.status === 'declined' ? 'destructive' : 'secondary'}>
                        {request.status}
                      </Badge>
                    </div>
                    <div className="mt-1 text-xs text-muted-foreground">
                      <span className="break-all">{request.email}</span>
                      <span className="mx-1.5">·</span>
                      <span>{formatTime(request.createdAt)}</span>
                    </div>
                    <div className="mt-3 grid grid-cols-2 gap-3 text-xs md:grid-cols-4">
                      <div>
                        <div className="text-muted-foreground">Ports</div>
                        <div className="font-mono text-foreground">{request.ports.join(', ') || '—'}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">SSL</div>
                        <div className="text-foreground">{request.ssl ? 'Yes' : 'No'}</div>
                      </div>
                      <div>
                        <div className="text-muted-foreground">Pool</div>
                        <div className="text-foreground">{request.poolMembers.length} member{request.poolMembers.length !== 1 ? 's' : ''}</div>
                      </div>
                      {request.assignedIP && (
                        <div>
                          <div className="text-muted-foreground">Assigned IP</div>
                          <div className="font-mono text-foreground">{request.assignedIP}</div>
                        </div>
                      )}
                      {request.requestType === 'add_port' && request.vipIP && (
                        <div>
                          <div className="text-muted-foreground">VIP IP</div>
                          <div className="font-mono text-foreground">{request.vipIP}</div>
                        </div>
                      )}
                    </div>
                    {request.poolMembers.length > 0 && (
                      <div className="mt-3 flex flex-wrap gap-1">
                        {request.poolMembers.map((pm) => (
                          <span key={pm.id} className="rounded-md bg-muted px-2 py-0.5 font-mono text-xs text-foreground">
                            {pm.ipAddress}{pm.port ? `:${pm.port}` : ''}
                          </span>
                        ))}
                      </div>
                    )}
                    {request.declineReason && (
                      <div className="mt-3 rounded-md bg-destructive/10 p-2 text-xs">
                        <span className="font-medium">Declined:</span> {request.declineReason}
                      </div>
                    )}
                  </div>
                  {request.status === 'pending' && (
                    <div className="flex shrink-0 flex-row gap-2 md:flex-col">
                      <Button size="sm" onClick={() => handleApprove(request)} disabled={isProcessing}>
                        <CheckCircle className="mr-2 h-4 w-4" /> Approve
                      </Button>
                      <Button size="sm" variant="destructive" onClick={() => { setSelectedRequest(request); setShowDeclineDialog(true); }} disabled={isProcessing}>
                        <XCircle className="mr-2 h-4 w-4" /> Decline
                      </Button>
                    </div>
                  )}
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>

      <Dialog open={showDeclineDialog} onOpenChange={setShowDeclineDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Decline VIP Request</DialogTitle>
            <DialogDescription>Please provide a reason for declining this request.</DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="declineReason">Reason *</Label>
            <Textarea id="declineReason" value={declineReason} onChange={(e) => setDeclineReason(e.target.value)} placeholder="Enter reason for declining..." rows={4} />
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowDeclineDialog(false)}>Cancel</Button>
            <Button variant="destructive" onClick={handleDecline} disabled={isProcessing}>Decline Request</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={showRenameDialog} onOpenChange={setShowRenameDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>VIP name already exists</DialogTitle>
            <DialogDescription>
              {duplicateMessage || 'A VIP with this name already exists on F5.'} Enter a different VIP name to use for this approval. Only the name will change; all other request details stay the same.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-2">
            <Label htmlFor="newVipName">New VIP Name</Label>
            <Input id="newVipName" value={newVipName} onChange={(e) => setNewVipName(e.target.value)} placeholder="new-vip-name" />
            <p className="text-xs text-muted-foreground">Original: <code className="font-mono">{renameTarget?.vipName}</code></p>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowRenameDialog(false)}>Cancel</Button>
            <Button onClick={handleRenameApprove} disabled={isProcessing || !newVipName.trim()}>Approve with new name</Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Layout>
  );
};

export default Admin;
