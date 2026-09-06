# BasaD F5 VIP Portal - frontend

Vite + React + TypeScript app (Tailwind, shadcn/ui). Served by the Tornado
backend in production; run standalone during development.

```bash
npm install
npm run dev      # http://localhost:8080, proxies the API to :8889
npm run build    # production bundle into dist/
```

The dev-server proxy targets and the allowed host are configured in
`vite.config.ts`. UI primitives under `src/components/ui/` are shadcn/ui
components - see `../THIRD-PARTY-NOTICES.md`.