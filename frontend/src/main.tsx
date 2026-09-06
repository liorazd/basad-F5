import { createRoot } from "react-dom/client";
import App from "./App.tsx";
import "./index.css";

// Apply the persisted theme before the first paint so users don't flash the
// wrong palette on full reloads. Mirrors ThemeContext's resolution rules.
(() => {
  try {
    const stored = window.localStorage.getItem('ui_theme');
    const pref = stored === 'light' || stored === 'dark' ? stored : 'system';
    const dark =
      pref === 'dark' ||
      (pref === 'system' && window.matchMedia('(prefers-color-scheme: dark)').matches);
    document.documentElement.classList.toggle('dark', dark);
    document.documentElement.style.colorScheme = dark ? 'dark' : 'light';
  } catch {
    // localStorage may be blocked; fall back to default light theme.
  }
})();

createRoot(document.getElementById("root")!).render(<App />);
