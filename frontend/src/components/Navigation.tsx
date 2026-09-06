import { Link, useLocation } from 'react-router-dom';
import { cn } from '@/lib/utils';
import { FileText, Shield } from 'lucide-react';

export const Navigation = () => {
  const location = useLocation();

  return (
    <nav className="border-b border-border bg-card">
      <div className="container mx-auto px-4">
        <div className="flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            <img src="/basad-mark.png" alt="" className="h-6 w-6" />
            <span className="text-xl font-bold text-foreground">BasaD F5 VIP Manager</span>
          </div>
          <div className="flex gap-1">
            <Link
              to="/"
              className={cn(
                "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
                location.pathname === '/'
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <FileText className="h-4 w-4" />
              VIP Request
            </Link>
            <Link
              to="/admin"
              className={cn(
                "flex items-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors",
                location.pathname === '/admin'
                  ? "bg-primary text-primary-foreground"
                  : "text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              )}
            >
              <Shield className="h-4 w-4" />
              Admin
            </Link>
          </div>
        </div>
      </div>
    </nav>
  );
};
