import { ReactNode } from 'react';
import { Link } from 'react-router-dom';
import { Layout } from './Layout';
import { Card } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { useAuth } from '@/contexts/AuthContext';
import { Shield, Loader2 } from 'lucide-react';

const Loading = () => (
  <Layout>
    <div className="container mx-auto px-4 py-12">
      <Card className="mx-auto max-w-md p-8 text-center">
        <Loader2 className="mx-auto mb-3 h-8 w-8 animate-spin text-primary" />
        <p className="text-sm text-muted-foreground">Checking identity...</p>
      </Card>
    </div>
  </Layout>
);

const LoginRequired = () => (
  <Layout>
    <div className="container mx-auto px-4 py-12">
      <Card className="mx-auto max-w-md p-8 text-center">
        <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full bg-primary/10">
          <Shield className="h-7 w-7 text-primary" />
        </div>
        <h2 className="text-lg font-semibold text-foreground">Login required</h2>
        <p className="mt-2 text-sm text-muted-foreground">
          Log in as an F5 admin via the Admin page, or access this app through
          your APM portal.
        </p>
        <Button asChild className="mt-5">
          <Link to="/admin">Go to login</Link>
        </Button>
      </Card>
    </div>
  </Layout>
);

export const RequireAuth = ({ children }: { children: ReactNode }) => {
  const { role, loading } = useAuth();
  if (loading) return <Loading />;
  if (role === 'admin') return <>{children}</>;
  return <LoginRequired />;
};

export const RequireAdmin = ({ children }: { children: ReactNode }) => {
  const { role, loading } = useAuth();
  if (loading) return <Loading />;
  if (role === 'admin') return <>{children}</>;
  return <LoginRequired />;
};
