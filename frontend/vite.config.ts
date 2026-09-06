import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

// Several API prefixes collide with client-side routes: /admin is both the
// login page and /admin/login+/admin/logout, and /audit is both a page and an
// API endpoint. A top-level browser navigation (or an F5 APM landing redirect)
// to one of those used to be forwarded to Tornado, which has no such handler
// and replies with its bare built-in 404 page -- the "empty page" users hit on
// first login. Navigations ask for text/html; the app's fetch() calls do not,
// so serve the SPA shell for the former and proxy only the latter.
const backendProxy = {
  target: 'http://localhost:8889',
  changeOrigin: true,
  bypass: (req: { headers: Record<string, string | string[] | undefined> }) => {
    const accept = String(req.headers.accept || '');
    return accept.includes('text/html') ? '/index.html' : undefined;
  },
};

// https://vitejs.dev/config/
export default defineConfig(() => ({
  server: {
    host: "::",
    port: 8080,
    allowedHosts: ['vip-portal.example.org'],
    proxy: Object.fromEntries(
      ['/admin', '/vipcreation', '/viprequest', '/me', '/f5', '/audit', '/access-request', '/cache'].map(
        (prefix) => [prefix, backendProxy]
      )
    ),
  },
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
}));
