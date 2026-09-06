import { useEffect, useState } from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { useAuth, Role } from '@/contexts/AuthContext';
import { ThemeToggle } from '@/components/ThemeToggle';
import { APIService } from '@/services/api.service';
import { Button } from '@/components/ui/button';
import {
  Shield,
  FilePlus,
  PlusCircle,
  ShieldCheck,
  ListChecks,
  History,
  Activity,
  LayoutDashboard,
  LogIn,
  LogOut,
} from 'lucide-react';

const formatRemaining = (expiresAt: number, nowMs: number): string => {
  const seconds = Math.max(0, Math.floor(expiresAt - nowMs / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m`;
  const hours = Math.floor(minutes / 60);
  const remMinutes = minutes % 60;
  return remMinutes ? `${hours}h ${remMinutes}m` : `${hours}h`;
};

interface NavItem {
  to: string;
  label: string;
  icon: typeof Shield;
  description: string;
  roles: Role[];
}

const navItems: NavItem[] = [
  { to: '/', label: 'Dashboard', icon: LayoutDashboard, description: 'Overview of every environment', roles: ['admin', 'anonymous'] },
  { to: '/new-vip', label: 'New VIP', icon: FilePlus, description: 'Submit a new VIP request', roles: ['admin', 'anonymous'] },
  { to: '/add-port', label: 'Add Port', icon: PlusCircle, description: 'Request a port on an existing VIP', roles: ['admin', 'anonymous'] },
  { to: '/replace-cert', label: 'Replace SSL Cert', icon: ShieldCheck, description: 'Replace an existing client-SSL certificate', roles: ['admin'] },
  { to: '/status', label: 'VIP Status', icon: Activity, description: 'Live VIP/pool/member health', roles: ['admin'] },
  { to: '/admin', label: 'Admin Queue', icon: ListChecks, description: 'Review and approve VIP requests (admin only)', roles: ['admin'] },
  { to: '/audit', label: 'Audit Log', icon: History, description: 'See and revert past actions (admin only)', roles: ['admin'] },
  { to: '/admin', label: 'Login', icon: LogIn, description: 'Sign in with your F5 credentials', roles: ['anonymous'] },
];

interface SidebarProps {
  onNavigate?: () => void;
}

export const Sidebar = ({ onNavigate }: SidebarProps) => {
  const location = useLocation();
  const navigate = useNavigate();
  const { role, username, loading, expiresAt, refresh } = useAuth();
  const visible = navItems.filter((item) => item.roles.includes(role));
  const [now, setNow] = useState(() => Date.now());
  const [signingOut, setSigningOut] = useState(false);

  const handleLogout = async () => {
    if (signingOut) return;
    setSigningOut(true);
    try {
      await APIService.adminLogout();
      await refresh();
      onNavigate?.();
      navigate('/admin');
    } finally {
      setSigningOut(false);
    }
  };

  useEffect(() => {
    if (!expiresAt || role !== 'admin') return;
    const id = window.setInterval(() => setNow(Date.now()), 30 * 1000);
    return () => window.clearInterval(id);
  }, [expiresAt, role]);

  const remaining = expiresAt && role === 'admin' ? formatRemaining(expiresAt, now) : null;
  const expiringSoon = expiresAt && role === 'admin' && expiresAt - now / 1000 <= 300;

  return (
    <aside className="flex h-screen w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar text-sidebar-foreground">
      <div className="flex items-center justify-between gap-3 border-b border-sidebar-border px-5 py-4">
        <div className="flex items-center gap-3">
          <img src="/basad-mark.png" alt="" className="h-9 w-9 shrink-0" />
          <div>
            <div className="text-sm font-semibold leading-tight text-sidebar-foreground/95">BasaD F5</div>
            <div className="text-[11px] leading-tight text-sidebar-foreground/60">VIP Manager</div>
          </div>
        </div>
      </div>
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-3 py-4">
        {visible.map((item) => {
          const active = item.to === '/' ? location.pathname === '/' : location.pathname.startsWith(item.to);
          const Icon = item.icon;
          return (
            <Link
              key={item.to}
              to={item.to}
              onClick={onNavigate}
              title={item.description}
              className={cn(
                'group relative flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors',
                active
                  ? 'bg-sidebar-accent font-medium text-sidebar-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground'
              )}
            >
              {active && (
                <span className="absolute inset-y-1.5 left-0 w-0.5 rounded-r bg-brand" aria-hidden="true" />
              )}
              <Icon className={cn('h-4 w-4 shrink-0', active && 'text-brand')} />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
      <div className="space-y-2 border-t border-sidebar-border px-4 py-3 text-xs">
        {loading ? (
          <div className="text-sidebar-foreground/60">Checking identity...</div>
        ) : (
          <>
            <div className="font-medium text-sidebar-foreground/95">{username || 'Not signed in'}</div>
            <div className="text-sidebar-foreground/60">role: <span className="font-mono">{role}</span></div>
            {remaining && (
              <div className={cn('text-sidebar-foreground/60', expiringSoon && 'text-destructive')}>
                session: <span className="font-mono">{remaining}</span>
              </div>
            )}
          </>
        )}
        <div className="pt-1">
          <ThemeToggle />
        </div>
        {role === 'admin' && (
          <Button
            variant="ghost"
            size="sm"
            disabled={signingOut}
            onClick={handleLogout}
            className="mt-1 w-full justify-start gap-2 text-sidebar-foreground/80 hover:bg-sidebar-accent/60 hover:text-sidebar-foreground"
          >
            <LogOut className="h-4 w-4" />
            <span>{signingOut ? 'Signing out...' : 'Sign out'}</span>
          </Button>
        )}
      </div>
    </aside>
  );
};
