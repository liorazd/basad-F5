import { F5Config } from '@/types/vip';

const envString = (value: string | undefined): string => (value || '').trim();
const envInt = (value: string | undefined, fallback: number): number => {
  const parsed = Number.parseInt(envString(value), 10);
  return Number.isFinite(parsed) ? parsed : fallback;
};

// Frontend config should not hardcode infrastructure addresses or credentials.
export const f5Config: F5Config = {
  dmzUrl: envString(import.meta.env.VITE_F5_DMZ_URL),
  dcUrl: envString(import.meta.env.VITE_F5_DC_URL),
  username: envString(import.meta.env.VITE_F5_USERNAME),
  password: envString(import.meta.env.VITE_F5_PASSWORD),
};

const backendHost = envString(import.meta.env.VITE_BACKEND_URL).replace(/\/$/, '');

export const apiConfig = {
  tornadoApiUrl: backendHost ? `${backendHost}/vipcreation` : '/vipcreation',
  emailSmtpHost: envString(import.meta.env.VITE_EMAIL_SMTP_HOST) || 'smtp.example.org',
  emailSmtpPort: envInt(import.meta.env.VITE_EMAIL_SMTP_PORT, 1040),
};

// F5 Target options for admin login
export const F5_TARGETS = {
  DMZ: 'dmz',
  LAN: 'lan',
} as const;
