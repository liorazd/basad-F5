import { ReactNode, useState } from 'react';
import { Sidebar } from './Sidebar';
import { Button } from '@/components/ui/button';
import { ThemeToggle } from '@/components/ThemeToggle';
import { Menu, X } from 'lucide-react';

interface LayoutProps {
  children: ReactNode;
}

export const Layout = ({ children }: LayoutProps) => {
  const [mobileOpen, setMobileOpen] = useState(false);

  const closeMobile = () => setMobileOpen(false);

  return (
    <div className="min-h-screen bg-background">
      {/* Mobile top bar (visible below md) */}
      <div className="flex h-14 items-center justify-between border-b border-border bg-card px-4 md:hidden">
        <div className="flex items-center gap-2">
          <img src="/basad-mark.png" alt="" className="h-5 w-5" />
          <span className="text-sm font-semibold text-foreground">
            BasaD F5 VIP
          </span>
        </div>
        <div className="flex items-center gap-2">
          <ThemeToggle variant="icon" />
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setMobileOpen((v) => !v)}
            aria-label={mobileOpen ? 'Close menu' : 'Open menu'}
          >
            {mobileOpen ? (
              <X className="h-5 w-5" />
            ) : (
              <Menu className="h-5 w-5" />
            )}
          </Button>
        </div>
      </div>

      <div className="flex">
        {/* Mobile drawer overlay */}
        {mobileOpen && (
          <div
            className="fixed inset-0 z-30 bg-black/40 md:hidden"
            onClick={closeMobile}
            aria-hidden="true"
          />
        )}

        {/* Sidebar:
            - md+: always visible, in normal flow
            - mobile: fixed drawer that slides in when mobileOpen */}
        <div
          className={`
            fixed inset-y-0 left-0 z-40 transition-transform duration-200
            ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}
            md:static md:translate-x-0
          `}
        >
          <Sidebar onNavigate={closeMobile} />
        </div>

        {/* Main content */}
        <main className="min-h-screen flex-1">{children}</main>
      </div>
    </div>
  );
};
