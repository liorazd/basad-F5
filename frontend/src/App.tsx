import { Toaster } from "@/components/ui/toaster";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { VIPsProvider } from "@/contexts/VIPsContext";
import { StatusProvider } from "@/contexts/StatusContext";
import { AuthProvider } from "@/contexts/AuthContext";
import { ThemeProvider } from "@/contexts/ThemeContext";
import { RequireAuth, RequireAdmin } from "@/components/RequireAuth";
import Dashboard from "./pages/Dashboard";
import VIPRequest from "./pages/VIPRequest";
import AddPort from "./pages/AddPort";
import ReplaceCert from "./pages/ReplaceCert";
import Admin from "./pages/Admin";
import Audit from "./pages/Audit";
import Status from "./pages/Status";
import NotFound from "./pages/NotFound";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <ThemeProvider>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <AuthProvider>
          <VIPsProvider>
            <StatusProvider>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/new-vip" element={<VIPRequest />} />
              <Route path="/add-port" element={<AddPort />} />
              <Route
                path="/replace-cert"
                element={
                  <RequireAuth>
                    <ReplaceCert />
                  </RequireAuth>
                }
              />
              <Route
                path="/status"
                element={
                  <RequireAuth>
                    <Status />
                  </RequireAuth>
                }
              />
              <Route path="/admin" element={<Admin />} />
              <Route
                path="/audit"
                element={
                  <RequireAdmin>
                    <Audit />
                  </RequireAdmin>
                }
              />
              <Route path="*" element={<NotFound />} />
            </Routes>
            </StatusProvider>
          </VIPsProvider>
        </AuthProvider>
      </BrowserRouter>
    </TooltipProvider>
    </ThemeProvider>
  </QueryClientProvider>
);

export default App;
